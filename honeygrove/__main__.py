from honeygrove import log
from honeygrove.config import Config
from honeygrove.core.HoneyAdapter import BrokerWatcher
from honeygrove.core.ServiceController import ServiceController
from honeygrove.services.SSHService import load_database, save_database

import atexit
import os
import threading


def shutdown():
    log.info("Shutting down")
    save_database()
    quit()


if __name__ == '__main__':
    """
    Startup module. Name needs to be like this for the automatic import of the other modules.
    """

    log.info("Starting HoneyGrove")

    if not os.getuid() == 0:
        print("[-] Honeygrove must be run as root.\n[!] Starting anyway!\n[!] Some functions may not work correctly!")

    # Initialize Services
    controller = ServiceController()

    # Initialize Broker
    brokerThread = threading.Thread(target=BrokerWatcher.broker_status_loop, args=(controller,))
    brokerThread.name = "BrokerThread"
    brokerThread.start()

    # Start Services
    for service in Config.general.enabled_services:
        controller.startService(service)

    # XXX: Why is this necessary here?
    # Load ssh database
    load_database()
    atexit.register(shutdown)

