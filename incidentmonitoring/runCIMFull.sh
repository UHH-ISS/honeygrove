#!/bin/bash
trap 'kill $(jobs -p)' EXIT

cd ..

echo "Rising the maximum memory that virtual machines are allowed to map"
sudo sysctl -w vm.max_map_count=262144

echo "Start CIMBrokerEndpoint..."
python3 -m incidentmonitoring "$@" &

echo "Start EK-Stack..."
docker-compose -f ./incidentmonitoring/EKStack/docker-compose.yml up --build


