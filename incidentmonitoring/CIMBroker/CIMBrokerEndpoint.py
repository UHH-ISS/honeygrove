import sys, os
sys.path.append(os.path.abspath(__file__ + "/../../.."))

from pybroker import *
import incidentmonitoring.CIMBroker.CIMBrokerConfig as CIMBrokerConfig
from incidentmonitoring.CIMBroker.CIMBrokerConfig import es
import json
import base64
from datetime import datetime
from incidentmonitoring.MHR.MalwareLookup import MalwareLookup
from incidentmonitoring.EKStack.elasticsearch.config.scripts import ElasticsearchMapping


class CIMBrokerEndpoint:
    # endpoint
    # Need Global Scope due multihop Broker
    listenEndpoint = endpoint("listenEndpoint")

    # "logs" and "files" are the Topics we subscribe.
    logsQueue = message_queue("logs", listenEndpoint, GLOBAL_SCOPE)
    fileQueue = message_queue("files", listenEndpoint, GLOBAL_SCOPE)

    @staticmethod
    def connectEndpoints():
        # for peering
        CIMBrokerEndpoint.listenEndpoint.listen(CIMBrokerConfig.BrokerComport, CIMBrokerConfig.BrokerComIP)

    @staticmethod
    def getLogs():
        """
        receives logs what were send over the logstopic
        :return:
        """
        return CIMBrokerEndpoint.logsQueue.want_pop()

    @staticmethod
    def getFile():
        """
        receives a file that was sent over the filestopic
        """
        return CIMBrokerEndpoint.fileQueue.want_pop()

    @staticmethod
    def processMalwareFile(fileQueue):
        """
        receives malwarefiles over the "filesQueue" messagetopic
        and saves them with consecutive timestamps

        :param: fileQueue
        """
        timestamp = datetime.utcnow().isoformat()
        for msg in fileQueue:
            for m in msg:
                with open('./incidentmonitoring/ressources/%s.file' % timestamp, 'wb') as afile:
                    afile.write(base64.b64decode(str(m))) 
            MalwareLookup.hashingFile()

    @staticmethod
    def processLogFiles(logQueue):
        """
        receives logfiles over the "logsQueue" messagetopic
        and saves them in a JSON-file

        :param logQueue:
        """

        for msg in logQueue:
            for entry in msg:
                "{0}".format(entry)
                print("Log: ",entry)

                # allows us to keep the doc_types of our logs to distinguish them later in Kibana.
                # Otherwise we would have to use a common doc_type. With an doc_type you can partition the index.
                output_logs = json.loads(str(entry))  # the JSON-String logs
                if 'index' not in output_logs:
                    pass
                elif 'index' in output_logs:
                    i = (output_logs['index'])
                    if '_type' in i:
                        global t
                        t = (i['_type'])

                # if connection to Elasticsearch is interrupted, cache logs into logs.json to prevent data loss.
                if not ElasticsearchMapping.check_ping():
                    print('\033[91m' + "The logs will be saved in the logs.json under "
                                       "/incidentmonitoring/ressources." + '\033[0m')
                    with open(
                            ''
                            './incidentmonitoring/ressources/logs.json', 'a') as outfile:
                        outfile.write(str(entry))
                        outfile.write('\n')

                else:
                    try:
                        # send logs into Elasticsearch
                        month = datetime.utcnow().strftime("%Y-%m")
                        indexname = "honeygrove-" + month
                        es.index(index=indexname, doc_type=t, body=output_logs)

                    except Exception:
                        pass

    @staticmethod
    def messageHandling():
        while True:
            msgs = CIMBrokerEndpoint.getLogs()
            msgs1 = CIMBrokerEndpoint.getFile()

            CIMBrokerEndpoint.connectEndpoints()
            CIMBrokerEndpoint.processMalwareFile(msgs1)
            CIMBrokerEndpoint.processLogFiles(msgs)
