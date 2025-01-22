CLANG = clang
CFLAGS = -g -O2 -Wall
BPFTARGETFLAG = -target bpf

LIBBPF_BUILD = /home/users/jimsiak/ebpf/other-examples/libbpf/build
INCFLAGS = -I . -I$(LIBBPF_BUILD)
LFLAGS = -lelf -lz

BPFTOOL = /usr/sbin/bpftool

.PHONY: clean all

all: final_mmap final_read

vmlinux.h: /sys/kernel/btf/vmlinux
	$(BPFTOOL) btf dump file $< format c > $@

final_mmap.bpf.o: final_mmap.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(BPFTARGETFLAG) $(INCFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@

final_mmap.skel.h: final_mmap.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

final_mmap.o: final_mmap.c final_mmap.skel.h
	$(CLANG) $(CFLAGS) $(INCFLAGS) -c $< -o $@

final_mmap: final_mmap.o $(LIBBPF_BUILD)/libbpf.a
	$(CLANG) $(CFLAGS) $< $(word 2,$^) $(LFLAGS) -o $@

final_read.bpf.o: final_read.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(BPFTARGETFLAG) $(INCFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@

final_read.skel.h: final_read.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

final_read.o: final_read.c final_read.skel.h
	$(CLANG) $(CFLAGS) $(INCFLAGS) -c $< -o $@

final_read: final_read.o $(LIBBPF_BUILD)/libbpf.a
	$(CLANG) $(CFLAGS) $< $(word 2,$^) $(LFLAGS) -o $@

clean:
	rm -fv vmlinux.h
	rm -fv final_mmap.bpf.o final_mmap.skel.h final_mmap.o final_mmap
	rm -fv final_read.bpf.o final_read.skel.h final_read.o final_read
