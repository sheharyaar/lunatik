Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2204"
  config.vm.provider "libvirt" do |v|
    v.memory = 4096
    v.cpus = 8
  end
  config.vm.synced_folder "./", "/home/vagrant/lunatik", type: "rsync"

  # trigger to run after "vagrant up" but before provisioning to setup routing rules
  # for internet access
  config.trigger.before :up do |t|
    t.info = "Setting up network routing rules"
    t.run = {path: "vagrant-setup.sh"}
  end

  # trigger to run after "vagrant halt" to destroy the routing rules
  config.trigger.after [:halt, :destroy] do |t|
    t.info = "Cleaning up network routing rules"
    t.run = {path: "vagrant-cleanup.sh"}
  end

  # prerequisites setup for building lunatik
  config.vm.provision "shell", inline: <<-SHELL
    cd /home/vagrant/lunatik
    rm -rf lua/
    rm -rf klibc/
    git submodule update --init --recursive
    chown -R vagrant:vagrant lua/
    chown -R vagrant:vagrant klibc/

    apt update
    apt install --no-install-recommends -y \
    git build-essential lua5.4 dwarves clang \
    llvm libelf-dev \
    linux-headers-$(uname -r) \
    linux-tools-common linux-tools-$(uname -r) \
    pkg-config libpcap-dev m4
  SHELL
end
