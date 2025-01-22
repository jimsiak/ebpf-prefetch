#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef char stringkey[64];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, stringkey);
	__type(value, u32);
} pid_map SEC(".maps");

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

SEC("kprobe/filemap_get_pages")
int trace_filemap_get_pages(struct pt_regs *ctx)
{
	/*********************************************************************/
	/* First check if process name is 'FIXME' and requested filename     */
	/* is 'FIXME'                                                        */
	/*********************************************************************/
	unsigned char comm[56];

	bpf_get_current_comm(comm, sizeof(comm));

	if (my_strncmp(comm, 3, "fio") != 0)
		return 0;

	struct kiocb kiocb;
	bpf_probe_read(&kiocb, sizeof(kiocb), (struct kiocb *)PT_REGS_PARM1(ctx));

	const unsigned char *fp;
	unsigned char filename[56];
	fp = BPF_CORE_READ(kiocb.ki_filp, f_path.dentry, d_name.name);
	bpf_probe_read_kernel_str(filename, sizeof(filename), fp);

	if (my_strncmp(filename, 4, "test") != 0)
		return 0;

	/**************************************************************/
	/* OK we have "fc_vcpu 0" process and "Full.memfile" filename */
	/**************************************************************/
	bpf_printk("[ENTRY] filemap_fault comm: %s filename: %s", comm, filename);

	struct file **filp = &(kiocb.ki_filp);

	stringkey bring_page_key = "bring_page";
	int *bring_pages = bpf_map_lookup_elem(&pid_map, &bring_page_key);
	if (bring_pages != NULL && *bring_pages == 1) {
		bpf_force_page2cache(filp, &index_map);
		*bring_pages = 0;
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
