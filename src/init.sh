# ## Install Dependency: 
# - required package: make, gcc, build-essential (apt, yum)
# - [bcc](https://github.com/iovisor/bcc) library for python e-bpf
# ```
# # for ubuntu
# echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
# sudo apt-get update
# sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
# sudo apt-get install -y python3-bcc python3-pip
# # for RHEL/CentOS
# yum install -y bcc-tools libbcc-examples linux-headers-$(uname -r) python-bcc python-pip
# ```
# - pip install -r requirement.txt

OS=$(cat /etc/os-release|grep ID=|awk -F '=' '/^ID/ { print $2 }')
echo "Install Dependency for $OS"
if [[ $OS =~ "ubuntu" ]];then
    apt-get install -y gcc make build-essential jq
    echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list
    sudo apt-get update
    sudo apt-get install -y bcc-tools libbcc-examples linux-headers-$(uname -r)
    sudo apt-get install -y python3-bcc python3-pip
elif [[ $OS =~ "rhel" || $OS =~ "centos" ]];then
    yum install -y gcc make build-essential jq
    yum install -y bcc-tools libbcc-examples linux-headers-$(uname -r) python-bcc python-pip
fi

pip3 install -r requirement.txt
make all
echo OVERLAY_CIRD=$(cat /etc/cni/net.d/10-calico.conflist |jq ".plugins[0].ipam.ipv4_pools[0]")>> /etc/environment

# create binary file of python
pip3 install pyinstaller
pyinstaller router.py

tar cf router.tar dist