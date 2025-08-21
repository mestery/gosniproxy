FROM debian:trixie AS builder

# Install build dependencies
RUN DEBIAN_FRONTEND="noninteractive" apt-get update && apt-get install -y \
    tzdata \
    rsync \
    clang \
    libclang-dev \
    llvm \
    llvm-dev \
    libelf-dev \
    libbpf-dev \
    git \
    golang-go \
    gcc \
    flex \
    bison \
    cmake \
    python3 \
    libpcap-dev \
    linux-libc-dev \
    build-essential \
    wget \
    xz-utils \
    bc \
    make

# Detect architecture and prepare kernel headers
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then KARCH=x86; elif [ "$ARCH" = "aarch64" ]; then KARCH=arm64; else echo "Unsupported arch $ARCH"; exit 1; fi && \
    wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.10.tar.xz && \
    tar -xJf linux-6.10.tar.xz -C /tmp && \
    cd /tmp/linux-6.10 && make ARCH=$KARCH headers_install INSTALL_HDR_PATH=/usr && \
    rm -rf /tmp/linux-6.10 linux-6.10.tar.xz

# Set working directory
WORKDIR /app

# Copy only go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY . .

# Install bpf2go into $GOPATH/bin
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Add Go bin dir to PATH
ENV PATH=$PATH:/root/go/bin

# Build the Go application
RUN go generate ./... && go build -o gosniproxy .

FROM debian:trixie

# Copy the built binary from builder stage
COPY --from=builder /app/gosniproxy /usr/local/bin/gosniproxy

# Expose port 5443 for the proxy
EXPOSE 5443

# Run the application with new command line options
CMD ["/usr/local/bin/gosniproxy", "-listen-addr", "0.0.0.0:5443", "-backend-mapping", "example.com:127.0.0.1:8443", "-backend-mapping", "test.com:127.0.0.1:8444"]
