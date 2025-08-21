//
// Copyright (c) 2025, Kyle Mestery
// All rights reserved.
//
// SPDX-License-Identifier: MIT License
//

package main

import (
	"testing"
)

func TestExtractSNI(t *testing.T) {
	// This is a basic test to verify SNI extraction works
	// In a real implementation, we'd have more comprehensive tests
	sni := extractSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x80}) // Simplified TLS handshake
	if sni != "" {
		t.Errorf("Expected empty SNI, got %s", sni)
	}
}

func TestExtractHost(t *testing.T) {
	// This is a basic test to verify Host header extraction works
	host := extractHostFromHTTPRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if host != "example.com" {
		t.Errorf("Expected Host 'example.com', got %s", host)
	}
}
