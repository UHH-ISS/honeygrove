#!/bin/sh

echo "installing pyBroker..."
sudo apt-get update
pybroker_install.sh

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

echo "installing important packages..."
sudo apt-get install curl
sudo apt-get install whois
sudo apt install python3-pip
sudo pip3 install twisted
sudo pip3 install -U cryptography
sudo pip3 install hashlib
sudo pip3 install elasticsearch
sudo pip3 install elasticsearch-watcher
sudo apt-get update
