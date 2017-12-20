import sys, os
sys.path.append(os.path.abspath(__file__ + "/../../../../../.."))

import time
import socket
import signal
from datetime import datetime
from incidentmonitoring.CIMBroker.CIMBrokerConfig import es, ElasticIp, ElasticPort
from incidentmonitoring.EKStack.elasticsearch.config.scripts import WatcherAlerts

# Check if Elasticsearch on port 9200 is reachable
def check_ping():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ElasticIp, ElasticPort))
    if result == 0:
        pingstatus = True
    else:
        pingstatus = False
        print('\033[91m' + "The connection to Elasticsearch is interrupted" + '\033[0m')
    return pingstatus

# Define the mapping and load it into the Elasticsearch index
def loadMapping():
    mapping = '''{
        "mappings": {
            "_default_": {
                "properties": {
                    "@timestamp": {"type": "date", "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"},
                    "actual": {"type": "keyword"},
                    "filename": {"type": "keyword"},
                    "found_date": {"type": "date", "format": "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"},
                    "hash": {"type": "keyword"},
                    "honeypotID": {"type": "keyword"},
                    "infolink": {"type": "keyword"},
                    "ip": {"type": "ip"},
                    "key": {"type": "keyword"},
                    "percent": {"type": "integer"},
                    "port": {"type": "keyword"},
                    "request": {"type": "keyword"},
                    "request_type": {"type": "keyword"},
                    "response": {"type": "keyword"},
                    "service": {"type": "keyword"},
                    "successful": {"type": "keyword"},
                    "user": {"type": "keyword"}
                }
            }
        }
    }'''

    # Create an index with our mapping
    es.indices.create(index='honeygrove', ignore=400, body=mapping)


# Start with mapping if Elasticsearch is reachable and cluster status is ready ("yellow")
def readyToMap():
    try:
        if check_ping():
            health = es.cluster.health()
            if 'status' in health:
                h = (health['status'])
                if h == 'yellow' or h == 'green':
                    loadMapping()
                    print('\033[94m' + 'Mapping Complete.' + '\033[0m')

                    # Execute Watcher alerts script
                    print('\033[94m' + "Start Watcher Alerts..." + '\033[0m')
                    WatcherAlerts.WatcherAlerts.putWatch()

                else:
                    print('\033[91m' + "es-master cluster state is red" + '\033[0m')
                    # Wait 10 seconds and retry checking cluster state
                    time.sleep(10)
                    readyToMap()
        else:
            # Retry connection attempt every 10 seconds
            time.sleep(10)
            readyToMap()

    except:
        # Retry after an Exception every 30 seconds (Exception message can be ignored)
        print("")
        time.sleep(60)
        readyToMap()


# Load first log with timestamp to show the @timestamp in the Time-field name and prevent
# error messages on the Kibana Honeygrove Dashboard.
def loadFirstLogs():
    firstlog = {'@timestamp': datetime.utcnow().isoformat(),
                'actual': '',
                'filename': '',
                'found_date': datetime.utcnow().isoformat(),
                'hash': '',
                'honeypotID': '',
                'infolink': '',
                'ip': '127.0.0.1',
                'key': '',
                'percent': '',
                'port': '22',
                'request': '',
                'request_type': '',
                'response': '',
                'service': 'HTTP',
                'successful': '',
                'user': ''}
    es.index(index="honeygrove", doc_type='mapping', body=firstlog)

# Handler for system signals (Exit mapping with Ctr + C)
def signalHandler(signal, frame):
    sys.exit(0)


if __name__ == '__main__':

    signal.signal(signal.SIGINT, signalHandler)

    # Let Docker build up containers and try mapping after 60 seconds.
    time.sleep(1)

    # Start the mapping process
    print('\033[94m'+"Start Mapping..."+'\033[0m')
    readyToMap()
    loadFirstLogs()
