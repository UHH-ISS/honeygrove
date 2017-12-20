import threading
import time

from incidentmonitoring.CIMBroker.CIMBrokerEndpoint import CIMBrokerEndpoint


if __name__ == '__main__':

    #sets up the honeypot connectin at a Port and IP Specified in CIMBrokerConifg
    CIMBrokerEndpoint.messageHandling()
