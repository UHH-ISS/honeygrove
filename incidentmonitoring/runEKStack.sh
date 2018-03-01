#!/bin/bash

echo "Rising the maximum memory that virtual machines are allowed to map"
sudo sysctl -w vm.max_map_count=262144

echo "Starting EK-Stack..."
docker-compose -f ./EKStack/docker-compose.yml up --build
