#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

typedef char stringkey[64];
typedef char stringinput[128];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, stringkey);
	__type(value, u32);
} execve_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024*1024);
	__type(key, int);
	__type(value, stringinput);
} log_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024*1024);
	__type(key, int);
	__type(value, int);
} index_map SEC(".maps");

int my_strncmp(const unsigned char *cs, const unsigned int n, const char *ct)
{
	unsigned int i;

	for (i=0; i < n; i++)
		if (cs[i] != ct[i])
			return cs[i] < ct[i] ? -1 : 1;
	return 0;
}

int get_access(u32 process_pid)
{
	stringkey pid_key = "pid";
	u32 *saved_pid = bpf_map_lookup_elem(&execve_counter, &pid_key);
	return (saved_pid && *saved_pid == process_pid);
}

int get_key() {
	stringkey key = "key";
	int *key_val = bpf_map_lookup_elem(&execve_counter, &key);
	if (key_val == NULL)
		return -1;
	int res = *key_val;
	*key_val += 1;
	return res;
}

SEC("kprobe/filemap_fault")
int trace_filemap_fault(struct pt_regs *ctx)
{
	/*********************************************************************/
	/* First check if process name is 'fc_vcpu 0' and requested filename */
	/* is 'Full.memfile'                                                 */
	/*********************************************************************/
	unsigned char comm[56];

	bpf_get_current_comm(comm, sizeof(comm));

	//if (my_strncmp(comm, 12, "jimsiak-test") != 0)
	if (my_strncmp(comm, 9, "fc_vcpu 0") != 0)
		return 0;

	struct vm_fault vmf;
	bpf_probe_read(&vmf, sizeof(vmf), (struct vm_fault *)PT_REGS_PARM1(ctx));

	const unsigned char *fp;
	unsigned char filename[56];
	fp = BPF_CORE_READ(vmf.vma, vm_file, f_path.dentry, d_name.name);
	bpf_probe_read_kernel_str(filename, sizeof(filename), fp);

	//if (my_strncmp(filename, 14, "test-mmap.file") != 0)
	if (my_strncmp(filename, 12, "Full.memfile") != 0)
		return 0;

	/**************************************************************/
	/* OK we have "fc_vcpu 0" process and "Full.memfile" filename */
	/**************************************************************/
	bpf_printk("[ENTRY] filemap_fault comm: %s filename: %s", comm, filename);

	unsigned long addr = vmf.address;
	unsigned long offset = vmf.pgoff;

	stringkey pid_key = "pid";
	u32 *saved_pid = bpf_map_lookup_elem(&execve_counter, &pid_key);
	if (saved_pid == NULL) {
		u32 uid = bpf_get_current_pid_tgid();
		saved_pid = &uid;
		bpf_map_update_elem(&execve_counter, &pid_key, saved_pid, BPF_ANY);
	}

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message),
	             "%s: filemap_fault started with addr 0x%x and offset %lu", comm, addr, offset);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	struct file **filp = &((vmf.vma)->vm_file);

	stringkey bring_page_key = "bring_page";
	int *bring_pages = bpf_map_lookup_elem(&execve_counter, &bring_page_key);
	if (bring_pages != NULL && *bring_pages == 1) {
		bpf_force_page2cache(filp, &index_map);
		*bring_pages = 0;
	}

	return 0;
}

SEC("kretprobe/filemap_fault")
int trace_filemap_fault_exit(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	stringkey pid_key = "pid";
	bpf_map_delete_elem(&execve_counter, &pid_key);

	bpf_printk("filemap_fault exited");

	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: filemap_fault exited", comm);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);
	
	return 0;
}

SEC("kprobe/pagecache_get_page")
int trace_pagecache_get_page(struct pt_regs *ctx)
{

	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	int offset = PT_REGS_PARM3(ctx);

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: pagecache_get_page started with offset %d", comm, offset);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kretprobe/pagecache_get_page")
int trace_ret_pagecache_get_page(struct pt_regs *ctx) {
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	bpf_printk("pagecache_get_page exited");
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: pagecache_get_page exited", comm);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kprobe/page_cache_sync_ra")
int trace_page_cache_sync_ra_enter(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	//page_cache_sync_ra started!
	int req_count = 0;
	req_count = PT_REGS_PARM2(ctx);
	bpf_printk("page_cache_sync_ra started with req_count=%d", req_count);
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_sync_ra started with req_count=%d", comm, req_count);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kretprobe/page_cache_sync_ra")
int trace_page_cache_sync_ra_exit(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	//page_cache_sync_ra exits!
	bpf_printk("page_cache_sync_ra finished");
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_sync_ra exited", comm);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kprobe/page_cache_async_ra")
int trace_page_cache_async_ra_enter(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	//page_cache_async_ra started!
	int req_count = 0;
	req_count = PT_REGS_PARM3(ctx);
	bpf_printk("page_cache_async_ra started with req_count=%d", req_count);
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_async_ra started with req_count=%d", comm, req_count);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kretprobe/page_cache_async_ra")
int trace_page_cache_async_ra_exit(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	//page_cache_async_ra exits!
	bpf_printk("page_cache_async_ra finished");
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_async_ra exited", comm);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kprobe/do_page_cache_ra")
int trace_do_page_cache_ra(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	int req_size = PT_REGS_PARM2(ctx);
	int async_size = PT_REGS_PARM3(ctx);
	bpf_printk("do_page_cache_ra started with req_size=%d, async_size=%d", req_size, async_size);
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: do_page_cache_ra started with req_size=%d, async_size=%d", comm, req_size, async_size);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kprobe/page_cache_ra_unbounded")
int trace_page_cache_ra_unbounded(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	int nr_to_read = PT_REGS_PARM2(ctx);
	int lookahead_size = PT_REGS_PARM3(ctx);

	bpf_printk("page_cache_ra_unbounded started with nr_to_read=%d and lookahead_size=%d", nr_to_read, lookahead_size);
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_ra_unbounded started nr_to_read=%d and lookahead_size=%d", comm, nr_to_read, lookahead_size);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kretprobe/page_cache_ra_unbounded")
int trace_page_cache_ra_unbounded_exit(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	bpf_printk("page_cache_ra_unbounded exited");
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: page_cache_ra_unbounded exited", comm);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int trace_page_cache_lru(struct pt_regs *ctx)
{
	if (!get_access(bpf_get_current_pid_tgid()))
		return 0;

	int offset = PT_REGS_PARM3(ctx);

	bpf_printk("add_to_page_cache_lru started with offset : %d", offset);
	char comm[56];
	bpf_get_current_comm(comm, sizeof(comm));

	stringinput message = "";
	int key = get_key();
	BPF_SNPRINTF(message, sizeof(message), "%s: add_to_page_cache_lru started with offset : %d", comm, offset);
	bpf_map_update_elem(&log_file, &key, message, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
