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
make
```
