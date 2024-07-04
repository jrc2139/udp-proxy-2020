Vagrant.configure("2") do |config|
  # Get go version from env var
  go_version = ENV["go_version"]

  # config.vm.box = "freebsd/FreeBSD-12.3-STABLE"  # pfSense 2.6
  config.vm.guest = :freebsd
  # config.vm.box_version = "2022.09.23"
  config.vm.box = "generic-x64/freebsd14"
  # config.vm.box = "generic/freebsd14"
  config.vm.box_version = "4.3.12"
  config.ssh.shell = "sh"
  config.vm.provision "shell", inline: <<-SHELL
    pkg install -y git gmake libpcap binutils
    # amd64-binutils

    # aarch64-gcc9  \
    #    aarch64-binutils arm-gnueabi-binutils binutils \
    #   armv7-freebsd-sysroot aarch64-freebsd-sysroot

    # Manually install go
    DIST="go#{go_version}.freebsd-amd64.tar.gz"
    mkdir -p ~/go

    # Download archive
    cd ~/
    fetch "https://go.dev/dl/${DIST}"

    # Extract archive
    tar -C /usr/local -xf "${DIST}"

    # Clean up
    rm "${DIST}"

    # Set paths
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

    # Check if go installed
    go env
  SHELL
  # have to rsync our code over to build
  config.vm.synced_folder ".", "/home/vagrant/udp-proxy-2020", create: true, disabled: false, id: 'source-code', type: "rsync"
  # config.vm.provider :virtualbox do |vb|
  config.vm.provider :libvirt do |vb|
    # vb.name = "udp-proxy-2020-freebsd"
    # vb.gui = false
    # vb.customize ["modifyvm", :id, "--vram", "16", "--graphicscontroller", "vmsvga"]
    vb.cpus = 2
    vb.memory = 1024
  end
  # build the code.  we scp it back onto the host via our Makefile
  config.trigger.after :up do |trigger|
    trigger.info = "building pfSense/FreeBSD binary..."
    trigger.name = "build-binary"
    trigger.run = {inline: "vagrant rsync"}
    # trigger.run_remote = {inline: "sh -c 'export GOROOT=/usr/local/go && export GOPATH=${HOME}/go && export PATH=/usr/local/bin:${GOPATH}/bin:${GOROOT}/bin:${PATH} && cd udp-proxy-2020 && echo ${PATH} && gmake freebsd-binaries'"}
    trigger.run_remote = {inline: <<-SHELL
        # set go env vars
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:/usr/local/bin:$PATH

        # build
        cd udp-proxy-2020
        gmake freebsd-binaries
    SHELL
    }
  end
end

# -*- mode: ruby -*-
# vi: set ft=ruby :
