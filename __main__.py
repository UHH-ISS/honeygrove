import os
import threading

from honeygrove.core.HoneyAdapter import HoneyAdapter

if __name__ == '__main__':

    """
    Startup module. Name needs to be like this for the automatic import of the other modules.
    """
    if not os.getuid() == 0:
        print(
            "[-] Honeygrove must be run as root. \n[!] Starting anyway! \n[!] Some functions are not working correctly!")

    HoneyAdapter.init()
    commandThread = threading.Thread(target=HoneyAdapter.command_message_loop, args=())
    heartbeatThread = threading.Thread(target=HoneyAdapter.hearbeat, args=())

    commandThread.name = "CommandThread"
    heartbeatThread.name = "HeartbeatThread"

    commandThread.start()
    heartbeatThread.start()
