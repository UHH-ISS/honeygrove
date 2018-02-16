#!/bin/bash

cd ..

echo "Starting CIMBrokerEndpoint..."
python3 -m incidentmonitoring "$@"
