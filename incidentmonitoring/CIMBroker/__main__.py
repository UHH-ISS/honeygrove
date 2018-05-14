import sys, os
sys.path.append(os.path.abspath(__file__ + "/.."))

import threading
import time

from CIMBrokerEndpoint import CIMBrokerEndpoint


if __name__ == '__main__':

    #sets up the honeypot connectin at a Port and IP Specified in CIMBrokerConifg
    CIMBrokerEndpoint.messageHandling()
