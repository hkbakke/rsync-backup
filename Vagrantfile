Vagrant.configure("2") do |config|
    config.vm.box = "debian/jessie64"
    config.vm.hostname = "rsync-backup-dev"
    config.vm.network :private_network, type: "dhcp"
    config.vm.provision :shell, path: "bootstrap.sh"
    
    config.vm.provider "virtualbox" do |v|
        v.name = "rsync-backup-dev"
        v.gui = false
        v.memory = 1024
        v.cpus = 1
    end
end