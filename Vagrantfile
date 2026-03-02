Vagrant.configure("2") do |config|
  config.vm.box = "debian/trixie"
  config.vm.hostname = "gosniproxy-dev"

  # Forward ports for testing
  config.vm.network "private_network", type: "dhcp"

  # Configure a fixed IP for easier access
  config.vm.network "private_network", ip: "192.168.56.10"

  # Increase memory allocation
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end

  # Provision the VM with necessary packages
  config.vm.provision "shell", inline: <<-SHELL
    # Update package list
    apt-get update

    # Install required packages for building and testing
    apt-get install -y \
      build-essential \
      git \
      golang-go \
      libelf-dev \
      libbpf-dev \
      clang \
      curl \
      python3 \
      openssl

    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" \
      -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    # Add vagrant user to docker group
    usermod -aG docker vagrant

    # Create directory for our project
    mkdir -p /home/vagrant/gosniproxy

    # Set up Go environment
    export GOPATH=/home/vagrant/go
    export PATH=$PATH:$GOPATH/bin

    # Copy project files to VM
    cp -r /vagrant/* /home/vagrant/gosniproxy/

    # Change to project directory and build
    cd /home/vagrant/gosniproxy

    # Build the proxy (eBPF is Linux-only, disabled on macOS host)
    go build -o gosniproxy main.go

    echo "Vagrant environment setup complete!"
  SHELL

  # Sync the project directory to the VM
  config.vm.synced_folder "./", "/vagrant", type: "virtualbox"
end
