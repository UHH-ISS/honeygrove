#!/bin/sh

echo "Load logs.json into Elasticsearch index..."
curl -H 'Content-Type: application/x-ndjson' -XPOST 'localhost:9200/honeygrove/_bulk?pretty' --data-binary @logs.json
echo "Loading complete."
sleep 5
echo "Delete logs.json..."
rm -rf logs.json
echo "Deleting complete"