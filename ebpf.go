//go:build linux

//
// Copyright (c) 2025, Kyle Mestery
// All rights reserved.
//
// SPDX-License-Identifier: MIT License
//

package main

import (
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// --- Generate Go bindings from the eBPF C file.
// Run: go generate ./...
//
//go:generate bash -c "which bpf2go >/dev/null || (echo 'bpf2go not found. Install: go install github.com/cilium/ebpf/cmd/bpf2go@latest' && exit 1)"
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall" Proxy ./kern/proxy_kern.bpf.c -- -I/usr/include

type EBPFProgram struct {
	objs  ProxyObjects
	link  link.Link
	ready bool
}

func NewEBPFProgram() (*EBPFProgram, error) {
	// Allow unlimited locking so the kernel can pin/load maps/programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var e EBPFProgram

	spec, err := LoadProxy()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	if err := spec.LoadAndAssign(&e.objs, nil); err != nil {
		return nil, fmt.Errorf("load objs: %w", err)
	}

	e.ready = true
	return &e, nil
}

func (e *EBPFProgram) Start() error {
	if !e.ready {
		return fmt.Errorf("ebpf: not initialized")
	}
	return nil
}

func (e *EBPFProgram) Stop() error {
	if e.link != nil {
		_ = e.link.Close()
	}
	return e.objs.Close()
}

// OffloadPair inserts both sockets into the sockmap (keys 0 and 1 by default)
// and programs cookie->peer-key redirection so the kernel proxies between them.
func (e *EBPFProgram) OffloadPair(client, backend net.Conn) error {
	if !e.ready {
		return fmt.Errorf("ebpf not ready")
	}

	cfd, err := fdFromConn(client)
	if err != nil {
		return fmt.Errorf("get client fd: %w", err)
	}
	bfd, err := fdFromConn(backend)
	if err != nil {
		return fmt.Errorf("get backend fd: %w", err)
	}

	// Insert both sockets into the SOCKMAP
	var kDown uint32 = 0
	var kUp uint32 = 1

	// For SockMap, the "value" must be a *socket fd* (u32) understood specially by the kernel.
	// cilium/ebpf handles this if you pass an int (fd) as the value.
	if err := e.objs.SockMap.Update(&kDown, int(cfd), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sockmap update k=0: %w", err)
	}
	if err := e.objs.SockMap.Update(&kUp, int(bfd), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sockmap update k=1: %w", err)
	}

	// Get each socket's cookie
	cDown, err := getsockCookie(int(cfd))
	if err != nil {
		return fmt.Errorf("SO_COOKIE(client): %w", err)
	}
	cUp, err := getsockCookie(int(bfd))
	if err != nil {
		return fmt.Errorf("SO_COOKIE(backend): %w", err)
	}

	// Map sender cookie -> destination key
	if err := e.objs.Cookie2key.Update(&cDown, &kUp, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("cookie2key client->up: %w", err)
	}
	if err := e.objs.Cookie2key.Update(&cUp, &kDown, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("cookie2key up->client: %w", err)
	}

	tcpClient, ok := client.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("client is not *net.TCPConn")
	}
	if err := link.AttachSocketFilter(tcpClient, e.objs.ProxyRedir); err != nil {
		return fmt.Errorf("attach to client socket: %w", err)
	}

	tcpBackend, ok := backend.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("backend is not *net.TCPConn")
	}
	if err := link.AttachSocketFilter(tcpBackend, e.objs.ProxyRedir); err != nil {
		return fmt.Errorf("attach to backend socket: %w", err)
	}

	log.Printf("[eBPF] offloaded: client(fd=%d,cookie=%d)->key1  backend(fd=%d,cookie=%d)->key0",
		cfd, cDown, bfd, cUp)
	return nil
}

func fdFromConn(c net.Conn) (uintptr, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("unsupported conn type %T", c)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, err
	}

	var fd uintptr
	err = raw.Control(func(s uintptr) { fd = s })
	if err != nil {
		return 0, err
	}
	return fd, nil
}

// syscallConn is satisfied by *net.TCPConn, *net.UnixConn, etc.
type syscallConn interface {
	SyscallConn() (syscallRawConn, error)
}
type syscallRawConn interface {
	Control(func(uintptr)) error
	Read(func(uintptr) bool) error
	Write(func(uintptr) bool) error
}

func getsockCookie(fd int) (uint64, error) {
	var val uint64
	sz := uint32(unsafe.Sizeof(val))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_COOKIE),
		uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&sz)),
		0,
		)
	if errno != 0 {
		return 0, errno
	}
	return val, nil
}
