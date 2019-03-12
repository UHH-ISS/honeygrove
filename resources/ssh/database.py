from honeygrove import log
from honeygrove.config import Config

import json

database_path = Config.ssh.resource_database
lastLoginTime = dict()

def restore():
    global lastLoginTime
    try:
        with open(database_path, 'r') as fp:
            lastLoginTime = json.loads(fp.read())
    except FileNotFoundError:
        pass
    except Exception:
        # e.g. damaged json encoding
        log.err("Failed to load lastLoginTime from existing file \""+str(database_path)+"\"")


def save():
    try:
        with open(database_path, 'w') as fp:
            fp.write(json.dumps(lastLoginTime))
    except Exception:
        # e.g. insufficient write permissions, io error etc.
        log.err("Failed to write lastLoginTime to file \""+str(database_path)+"\"")
