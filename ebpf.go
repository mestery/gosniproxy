package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// EBPFProgram represents an eBPF program for connection offloading

type EBPFProgram struct {
	// Maps for storing socket information
	sockMap *ebpf.Map
	// Program references
	prog *ebpf.Program
	// Link to attach to socket operations
	link link.Link
}

// NewEBPFProgram creates a new eBPF program
func NewEBPFProgram() (*EBPFProgram, error) {
	// Raise the rlimit to allow loading of eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Create a new eBPF program
	prog, err := createEBPFProgram()
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF program: %w", err)
	}

	// Create the sockmap for connection offloading
	sockMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "sock_map",
		Type:       ebpf.SockMap,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sockmap: %w", err)
	}

	// Attach the program to a socket operation
	link, err := link.Kprobe("tcp_v4_connect", prog, nil)
	if err != nil {
		sockMap.Close()
		prog.Close()
		return nil, fmt.Errorf("failed to attach eBPF program: %w", err)
	}

	return &EBPFProgram{
		sockMap: sockMap,
		prog:    prog,
		link:    link,
	}, nil
}

// Start starts the eBPF program
func (e *EBPFProgram) Start() error {
	return nil
}

// Stop stops the eBPF program
func (e *EBPFProgram) Stop() error {
	e.link.Close()
	e.prog.Close()
	e.sockMap.Close()
	return nil
}

// createEBPFProgram creates the actual eBPF program bytecode
func createEBPFProgram() (*ebpf.Program, error) {
	// This is a simplified example of an eBPF program that would be used for socket offloading
	// In practice, you'd want to load this from a file or embed it properly
	insns := asm.Instructions{
		// Load the context pointer into register 1
		asm.LoadImm(asm.R1, 0, asm.DWord),
		// Return success (0)
		asm.Return(),
	}

	// Load the program
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "sock_offload",
		Type: ebpf.SocketFilter,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	return prog, nil
}

// Attach attaches the eBPF program to a socket by adding it to the sockmap
func (e *EBPFProgram) Attach(sockFd int) error {
	// Convert socket file descriptor to uint32 key for the sockmap
	key := uint32(sockFd)

	// Add the socket to the sockmap for offloading
	err := e.AddSocket(key, sockFd)
	if err != nil {
		return fmt.Errorf("failed to add socket to eBPF map: %w", err)
	}

	log.Printf("Successfully attached eBPF program to socket fd %d", sockFd)
	return nil
}

// GetSockMap returns the underlying sockmap for direct access
func (e *EBPFProgram) GetSockMap() *ebpf.Map {
	return e.sockMap
}

// Close cleans up the eBPF resources
func (e *EBPFProgram) Close() error {
	if e.link != nil {
		e.link.Close()
	}
	if e.sockMap != nil {
		e.sockMap.Close()
	}
	if e.prog != nil {
		e.prog.Close()
	}
	return nil
}

// AddSocket adds a socket to the eBPF map for offloading
func (e *EBPFProgram) AddSocket(key uint32, fd int) error {
	// Convert file descriptor to byte slice for eBPF map
	fdBytes := make([]byte, 4)
	fdBytes[0] = byte(fd)
	fdBytes[1] = byte(fd >> 8)
	fdBytes[2] = byte(fd >> 16)
	fdBytes[3] = byte(fd >> 24)

	// Add the socket to the sockmap
	err := e.sockMap.Update(key, fdBytes, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update sockmap: %w", err)
	}

	log.Printf("Successfully added socket %d with key %d to eBPF map", fd, key)
	return nil
}

// RemoveSocket removes a socket from the eBPF map
func (e *EBPFProgram) RemoveSocket(key uint32) error {
	// Remove the socket from the sockmap
	err := e.sockMap.Delete(key)
	if err != nil {
		return fmt.Errorf("failed to delete from sockmap: %w", err)
	}

	log.Printf("Successfully removed socket with key %d from eBPF map", key)
	return nil
}
