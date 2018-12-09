#!/bin/sh
# cancel installation if any command fails
# in case the script fails, some manual cleanup may be necessary (like rm -rf /tmp/broker)
set -e
echo "installing Broker..."
sudo apt-get update
sudo apt-get install build-essential libssl-dev libffi-dev python-dev cmake
cd /tmp/
mkdir broker
cd broker
git clone --recursive https://github.com/bro/broker ./broker-git --branch v1.0.1 
cd broker-git
./configure --with-python=/usr/bin/python3
make -j4 
sudo make install
cd ../..
rm -rf broker


echo "installing docker & docker-compose..."
sudo apt-get -y remove docker docker-engine
sudo apt-get update
sudo apt-get install apt-transport-https software-properties-common ca-certificates
sudo apt-get -f install
sudo apt-get install wget
wget https://download.docker.com/linux/ubuntu/gpg
sudo apt-key add gpg
echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable" | sudo tee -a /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-cache policy docker-ce
sudo apt-get -y install linux-image-extra-virtual linux-image-extra-$(uname -r)
sudo apt-get -y install docker-ce
sudo systemctl start docker.service
sudo systemctl enable docker.service
sudo docker run hello-world
sudo apt -y install docker-compose
# vagrant is the user that docker uses to run the elasticsearch containers
# this prevents the data nodes from crashing immediately because they could not write to this directory
sudo chown -R vagrant /var/honeygrove

echo "installing important packages..."
sudo apt-get install curl
sudo apt-get install whois
sudo apt install python3-pip
sudo pip3 install -U twisted
sudo pip3 install -U cryptography
sudo pip3 install "elasticsearch>=6.0.0,<7.0.0"
sudo pip3 install elasticsearch-watcher
sudo apt-get update
