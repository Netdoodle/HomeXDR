//go:build linux

// Package bpf holds the eBPF programs of the Linux process, network and DNS sensors and
// their bpf2go-generated loaders. The compiled objects (*_bpfel.o) and generated Go files
// are committed, so a normal `go build` needs no clang. To rebuild them after editing the
// C sources (needs clang, llvm-strip and the libbpf headers, e.g. `apt install clang llvm
// libbpf-dev`), run from this directory:
//
//	go generate ./...
//
// The programs are CO-RE (compiled once, relocated against the running kernel's BTF), so
// the same object works across kernel versions. See hx_vmlinux.h.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -tags linux Process process.bpf.c -- -I/usr/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -tags linux Network network.bpf.c -- -I/usr/include
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -tags linux Dns dns.bpf.c -- -I/usr/include
