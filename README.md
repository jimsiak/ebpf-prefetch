# ebpf-prefetch
An eBPF mechanism for augmenting Linux page prefetching

## How to run experiments
First you need to install bpftool. This can simply be done using apt:
```
apt-get update && apt-get install bpftool
```

Then you need to build libbpf. This can be done with the following commands:
```
git clone https://github.com/libbpf/libbpf
git checkout tags/v1.4.0 -b v1.4.0
git apply <provided patch>
cd src
mkdir ../build
OBJDIR=../build/ DESTDIR=../build/ make install
```
Then you need to apply the kernel patch, build and install the modified 5.15.19 kernel.

Finally, you can go into firecracker directory and build and run the ebpf tool:
```
cd firecracker
... modify the Makefile with the correct libbpf path...
make
./firecracker 0
```

Now in another terminal you need to execute a firecracker microVM. Once you do this and the
execution finishes you can kill the firecracker bpf utility and check the log.txt file.
