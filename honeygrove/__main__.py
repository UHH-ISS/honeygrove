from honeygrove import log
from honeygrove.core.HoneyAdapter import HoneyAdapter
from honeygrove.services.SSHService import load_database, save_database

import os
import threading
import atexit


def shutdownHoneyGrove():
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

    HoneyAdapter.init()
    commandThread = threading.Thread(target=HoneyAdapter.command_message_loop, args=())
    heartbeatThread = threading.Thread(target=HoneyAdapter.heartbeat, args=())

    commandThread.name = "CommandThread"
    heartbeatThread.name = "HeartbeatThread"

    commandThread.start()
    heartbeatThread.start()

    # XXX: Why is this necessary here?
    # Load ssh database
    load_database()
    atexit.register(shutdownHoneyGrove)

