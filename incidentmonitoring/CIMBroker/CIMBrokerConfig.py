from elasticsearch import Elasticsearch

# -*- coding: utf-8 -*-
"""
Config for CIMBrokerEnndpoint.
"""

BrokerComIP = "127.0.0.1"
BrokerComport = 34445


#This could be a central Server
BrokerCentralServerPeerIP = ""
BrokerCentralServerPeerPort = None

# initialize the standard Elasticsearch client
ElasticIp = "127.0.0.1"
ElasticPort = 9200
es = Elasticsearch([{'host': ElasticIp, 'port': ElasticPort}])
