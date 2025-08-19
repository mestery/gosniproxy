#!/bin/bash

# Build the eBPF program
mkdir -p build

cd kern

echo "Building eBPF program..."
clang -O2 -target bpf -c sockmap.bpf.c -o ../build/sockmap.bpf.o

echo "eBPF program built successfully to build/sockmap.bpf.o"