//
// Copyright (c) 2025, Kyle Mestery
//
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config holds proxy configuration
type Config struct {
	ListenAddr     string
	BackendMapping map[string]string // hostname -> backend address
	CertFile       string
	KeyFile        string
	EnableDTLS     bool
	EnableEBPF     bool
}

// Proxy represents the HTTP/TLS proxy
type Proxy struct {
	config       *Config
	listener     net.Listener
	dtlsListener *net.UDPConn
	wg           sync.WaitGroup
	quit         chan struct{}
	ebpfProgram  *EBPFProgram // eBPF program support
}

// SockMap represents an eBPF sockmap for connection offloading
// This is a simplified representation - in practice, you'd use a proper eBPF library
// like github.com/cilium/ebpf or github.com/iovisor/gobpf
// For now, we'll implement a mock version

type SockMap struct {
	entries map[string]net.Conn // hostname -> connection
}

func NewSockMap() *SockMap {
	return &SockMap{
		entries: make(map[string]net.Conn),
	}
}

func (sm *SockMap) Add(hostname string, conn net.Conn) {
	sm.entries[hostname] = conn
}

func (sm *SockMap) Get(hostname string) (net.Conn, bool) {
	conn, exists := sm.entries[hostname]
	return conn, exists
}

func (sm *SockMap) Remove(hostname string) {
	delete(sm.entries, hostname)
}

// NewProxy creates a new proxy instance
func NewProxy(config *Config) *Proxy {
	proxy := &Proxy{
		config: config,
		quit:   make(chan struct{}),
	}

	if config.EnableEBPF {
		ebpfProgram, err := NewEBPFProgram()
		if err != nil {
			log.Printf("Failed to initialize eBPF program: %v", err)
		} else {
			proxy.ebpfProgram = ebpfProgram
		}
	}

	return proxy
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	var err error

	// Create TCP listener for HTTP/TLS
	if p.listener, err = net.Listen("tcp", p.config.ListenAddr); err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}

	log.Printf("Starting proxy on %s", p.config.ListenAddr)

	// Start handling connections
	p.wg.Add(1)
	go func() {
		p.handleConnections()
	}()

	// If DTLS is enabled, start UDP listener
	if p.config.EnableDTLS {
		if p.dtlsListener, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 443}); err != nil {
			log.Printf("Warning: failed to create DTLS listener: %v", err)
		} else {
			p.wg.Add(1)
			go func() {
				p.handleDTLSConnections()
			}()
		}
	}

	return nil
}

// Stop stops the proxy server
func (p *Proxy) Stop() {
	close(p.quit)
	if p.listener != nil {
		p.listener.Close()
	}
	if p.dtlsListener != nil {
		p.dtlsListener.Close()
	}
	p.wg.Wait()
}

// handleConnections handles incoming TCP connections
func (p *Proxy) handleConnections() {
	defer p.wg.Done()

	for {
		select {
		case <-p.quit:
			return
		default:
			conn, err := p.listener.Accept()
			if err != nil {
				select {
				case <-p.quit:
					return
				default:
					log.Printf("Error accepting connection: %v", err)
				}
				continue
			}

			p.wg.Add(1)
			go func(c net.Conn) {
				defer p.wg.Done()
				p.handleConnection(c)
			}(conn)
		}
	}
}

// handleConnection handles a single TCP connection
func (p *Proxy) handleConnection(conn net.Conn) {
	// For now, we'll just read the first few bytes to determine if it's TLS
	// In a real implementation, we'd use more sophisticated detection
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		conn.Close()
		return
	}

	// Check if it's a TLS handshake (first byte is 0x16 for TLS handshake)
	isTLS := n > 0 && buf[0] == 0x16

	if isTLS {
		// Handle TLS connection
		p.handleTLSConnection(conn, buf[:n])
	} else {
		// Handle HTTP connection
		p.handleHTTPConnection(conn, buf[:n])
	}
}

// handleTLSConnection handles TLS connections
func (p *Proxy) handleTLSConnection(conn net.Conn, firstBytes []byte) {
	// Extract SNI from TLS handshake
	sni := extractSNI(firstBytes)
	if sni == "" {
		log.Printf("No SNI found in TLS handshake")
		conn.Close()
		return
	}

	log.Printf("TLS connection for SNI: %s", sni)

	// Get backend address based on SNI
	backendAddr, exists := p.config.BackendMapping[sni]
	if !exists {
		log.Printf("No backend configured for SNI: %s", sni)
		conn.Close()
		return
	}

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backendAddr, err)
		conn.Close()
		return
	}

	// If eBPF is enabled, offload connection to kernel
	if p.config.EnableEBPF && p.ebpfProgram != nil {
		// In a real implementation, we would:
		// 1. Add the connection to an eBPF sockmap
		// 2. Return control to kernel for handling
		// For now, we'll just proxy normally but log that offloading would happen
		p.offloadToKernel(conn, backendConn, sni)
	} else {
		// Proxy the connection normally
		p.proxyConnection(conn, backendConn)
	}
}

// handleHTTPConnection handles HTTP connections
func (p *Proxy) handleHTTPConnection(conn net.Conn, firstBytes []byte) {
	// Parse HTTP request to get Host header
	host := extractHostFromHTTPRequest(firstBytes)
	if host == "" {
		log.Printf("No Host header found in HTTP request")
		conn.Close()
		return
	}

	log.Printf("HTTP connection for Host: %s", host)

	// Get backend address based on Host
	backendAddr, exists := p.config.BackendMapping[host]
	if !exists {
		log.Printf("No backend configured for Host: %s", host)
		conn.Close()
		return
	}

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backendAddr, err)
		conn.Close()
		return
	}

	// If eBPF is enabled, offload connection to kernel
	if p.config.EnableEBPF && p.ebpfProgram != nil {
		// In a real implementation, we would:
		// 1. Add the connection to an eBPF sockmap
		// 2. Return control to kernel for handling
		// For now, we'll just proxy normally but log that offloading would happen
		p.offloadToKernel(conn, backendConn, host)
	} else {
		// Proxy the connection normally
		p.proxyConnection(conn, backendConn)
	}
}

// extractSNI extracts the Server Name Indication from TLS handshake
func extractSNI(data []byte) string {
	// This is a simplified implementation
	// In a real implementation, we'd parse the full TLS handshake
	if len(data) < 5 {
		return ""
	}

	// Check for TLS handshake
	if data[0] != 0x16 {
		return ""
	}

	// Look for SNI extension in the handshake
	// This is a simplified approach - real implementation would parse TLS structure properly
	for i := 5; i < len(data)-2; i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 { // SNI extension
			// Skip the length bytes and get the hostname
			i += 2
			if i < len(data)-1 {
				hostLen := int(data[i])<<8 | int(data[i+1])
				i += 2
				if i+hostLen <= len(data) {
					return string(data[i : i+hostLen])
				}
			}
		}
	}

	return ""
}

// extractHostFromHTTPRequest extracts the Host header from HTTP request
func extractHostFromHTTPRequest(data []byte) string {
	// Simple parsing of HTTP request to find Host header
	s := string(data)
	lines := strings.Split(s, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimPrefix(line, "Host:")
			host = strings.TrimSpace(host)
			return host
		}
	}

	return ""
}

// proxyConnection proxies data between two connections
func (p *Proxy) proxyConnection(clientConn net.Conn, backendConn net.Conn) {
	defer clientConn.Close()
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, backendConn)
		if err != nil {
			log.Printf("Error copying from backend to client: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(backendConn, clientConn)
		if err != nil {
			log.Printf("Error copying from client to backend: %v", err)
		}
	}()

	wg.Wait()
}

func (p *Proxy) waitForClose(a, b net.Conn) {
	// Block on either side closing; TCPConn has Read deadline logic if you want.
	buf := make([]byte, 1)
	_ = a.SetReadDeadline(time.Time{})
	_ = b.SetReadDeadline(time.Time{})
	// Wait for either side to error/EOF; then close both.
	_, _ = a.Read(buf)
	_ = a.Close()
	_ = b.Close()
}

func (p *Proxy) offloadToKernel(clientConn net.Conn, backendConn net.Conn, hostname string) {
	log.Printf("Offloading connection for %s to kernel via eBPF", hostname)

	if p.ebpfProgram == nil {
		ebpfProgram, err := NewEBPFProgram()
		if err != nil {
			log.Printf("Failed to create eBPF program: %v", err)
			_ = clientConn.Close()
			_ = backendConn.Close()
			return
		}
		p.ebpfProgram = ebpfProgram
		if err := p.ebpfProgram.Start(); err != nil {
			log.Printf("Failed to start eBPF program: %v", err)
			_ = clientConn.Close()
			_ = backendConn.Close()
			return
		}
	}

	if err := p.ebpfProgram.OffloadPair(clientConn, backendConn); err != nil {
		log.Printf("eBPF offload failed, falling back to userspace proxy: %v", err)
		p.proxyConnection(clientConn, backendConn)
		return
	}

	// The kernel now proxies between sockets. We just need to keep them open
	// until one side closes. A tiny waiter will close both on EOF/error/quit.
	go p.waitForClose(clientConn, backendConn)
}

// handleDTLSConnections handles incoming DTLS connections
func (p *Proxy) handleDTLSConnections() {
	defer p.wg.Done()

	for {
		select {
		case <-p.quit:
			return
		default:
			buf := make([]byte, 1500)
			n, addr, err := p.dtlsListener.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-p.quit:
					return
				default:
					log.Printf("Error reading DTLS packet: %v", err)
				}
				continue
			}

			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.handleDTLSConnection(addr, buf[:n])
			}()
		}
	}
}

// handleDTLSConnection handles a single DTLS connection
func (p *Proxy) handleDTLSConnection(addr *net.UDPAddr, data []byte) {
	log.Printf("Received DTLS packet from %s", addr)
	// For now, we'll just log it - real implementation would parse DTLS
	// and route based on SNI or other criteria
}

func main() {
	config := &Config{
		ListenAddr: "0.0.0.0:443",
		BackendMapping: map[string]string{
			"example.com": "127.0.0.1:8443",
			"test.com":    "127.0.0.1:8444",
		},
		CertFile:   "server.crt",
		KeyFile:    "server.key",
		EnableDTLS: true,
		EnableEBPF: true,
	}

	proxy := NewProxy(config)

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	log.Println("Shutting down proxy...")
	proxy.Stop()
}
