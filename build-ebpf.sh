#!/bin/bash

# Build the eBPF program
mkdir -p build

cd kern

echo "Building eBPF program..."
clang -O2 -target bpf -c proxy_kern.bpf.c -o ../build/proxy_kern.bpf.o

echo "eBPF program built successfully to build/proxy_kern.bpf.o"