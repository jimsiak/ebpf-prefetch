CLANG = clang
CFLAGS = -g -O2 -Wall
BPFTARGETFLAG = -target bpf

LIBBPF_BUILD = /home/users/jimsiak/ebpf/libbpf/build
INCFLAGS = -I . -I$(LIBBPF_BUILD)/usr/include
LFLAGS = -lelf -lz

BPFTOOL = /usr/sbin/bpftool

.PHONY: clean all

all: firecracker

vmlinux.h: /sys/kernel/btf/vmlinux
	$(BPFTOOL) btf dump file $< format c > $@

firecracker.bpf.o: firecracker.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(BPFTARGETFLAG) $(INCFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@

firecracker.skel.h: firecracker.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

firecracker.o: firecracker.c firecracker.skel.h
	$(CLANG) $(CFLAGS) $(INCFLAGS) -c $< -o $@

firecracker: firecracker.o $(LIBBPF_BUILD)/libbpf.a
	$(CLANG) $(CFLAGS) $< $(word 2,$^) $(LFLAGS) -o $@

jimsiak-test: jimsiak-test.c
	gcc -Wall -Wextra -o jimsiak-test jimsiak-test.c

clean:
	rm -fv vmlinux.h firecracker.bpf.o firecracker.skel.h firecracker.o firecracker
