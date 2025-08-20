# Go SNI Proxy
[![Build Status](https://github.com/mestery/gosniproxy/actions/workflows/build.yml/badge.svg)](https://github.com/mestery/gosniproxy/actions/workflows/build.yml)

A Go-based proxy server that handles HTTP and HTTPS connections based on Server Name Indication (SNI) for routing to different backends.

## Features

- HTTP/HTTPS proxying with SNI-based routing
- Support for DTLS connections
- eBPF SOCKMAP integration for connection offloading
- Graceful shutdown handling

## How eBPF Works in This Proxy

When `EnableEBPF` is set to true, the proxy will attempt to offload connections to the kernel using eBPF. In a real implementation:

1. An eBPF program would be loaded into the kernel
2. A SOCKMAP would be created to store connection information
3. When a new connection arrives, it would be added to the map
4. The kernel would handle the connection directly without going through userspace

This approach reduces CPU overhead and improves performance for high-volume connections.

## Building and Running with Docker

### Building the Container

To build the Docker container:

```bash
docker build -t gosniproxy .
```

### Running the Container

To run the proxy in a container:

```bash
# Run with default configuration (port 443)
docker run --privileged -p 443:443 gosniproxy

# Or run with custom configuration
# Note: You'll need to mount your certificate files and configure backends appropriately
docker run --privileged -p 443:443 -v /path/to/certs:/certs gosniproxy
```

> **Note**: The `--privileged` flag is required for eBPF functionality as it needs access to kernel resources.

## Usage

To run the proxy directly (without Docker):

```bash
./gosniproxy
```

The proxy listens on port 443 by default and routes based on SNI or Host headers to configured backends.

## Configuration

The proxy is configured via the `Config` struct in `main.go`. You can modify:

- `ListenAddr`: Address to listen on
- `BackendMapping`: Map of hostnames to backend addresses
- `CertFile` and `KeyFile`: TLS certificate files (for HTTPS)
- `EnableDTLS`: Enable DTLS support
- `EnableEBPF`: Enable eBPF connection offloading

## Building (without Docker)

To build the project:

```bash
go build -o gosniproxy main.go
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.