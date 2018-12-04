import broker
import CIMBroker.CIMBrokerConfig as CIMBrokerConfig
from CIMBroker.CIMBrokerConfig import es
import json
import base64
from datetime import datetime
from MHR.MalwareLookup import MalwareLookup
from PrepareES import PrepareES


class CIMBrokerEndpoint:
    # endpoint
    listenEndpoint = broker.Endpoint()

    # "logs" and "files" are the Topics we subscribe.
    logsQueue = listenEndpoint.make_subscriber("logs")
    fileQueue = listenEndpoint.make_subscriber("files")

    @staticmethod
    def connectEndpoints():
        # for peering
        CIMBrokerEndpoint.listenEndpoint.listen(CIMBrokerConfig.BrokerComIP, CIMBrokerConfig.BrokerComport)
    
    @staticmethod
    def getLogs():
        """
        receives logs what were send over the logstopic
        :return:
        """
        return CIMBrokerEndpoint.logsQueue.poll()

    @staticmethod
    def getFile():
        """
        receives a file that was sent over the filestopic
        """
        return CIMBrokerEndpoint.fileQueue.poll()

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
                with open('./ressources/%s.file' % timestamp, 'wb') as afile:
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

                # if connection to Elasticsearch is interrupted, cache logs into logs.json to prevent data loss.
                if not PrepareES.check_ping():
                    print('\033[91m' + "The logs will be saved in the logs.json under "
                                       "/incidentmonitoring/ressources." + '\033[0m')
                    with open(
                            ''
                            './incidentmonitoring/ressources/logs.json', 'a') as outfile:
                        outfile.write(str(entry))
                        outfile.write('\n')

                else:
                    try:
                        output_logs = json.loads(str(entry))                        
                        # send logs into Elasticsearch
                        month = datetime.utcnow().strftime("%Y-%m")
                        indexname = "honeygrove-" + month
                        es.index(index=indexname, doc_type="log_event", body=output_logs)

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
