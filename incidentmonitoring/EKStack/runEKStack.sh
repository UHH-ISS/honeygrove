#!/bin/bash
trap 'kill $(jobs -p)' SIGINT

echo "Rising the maximum memory that virtual machines are allowed to map"
sudo sysctl -w vm.max_map_count=262144

python3 ./elasticsearch/config/scripts/ElasticsearchMapping.py &

echo "Starting EKStack ..."
docker-compose up --build
