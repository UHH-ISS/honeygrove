from honeygrove import log
from honeygrove.config import Config

import json

dbfilePath = Config.resources_dir + "ssh_resources/database.json"
lastLoginTime = dict()


def restore():
    global lastLoginTime
    try:
        file = open(dbfilePath, 'r')
    except FileNotFoundError:
        pass
    else:
        try:
            lastLoginTime = json.loads(file.read())
        except Exception:
            # e.g. damaged json encoding
            log.err("Failed to load lastLoginTime from existing file \""+str(dbfilePath)+"\"")


def save():
    try:
        with open(dbfilePath, 'w') as fp:
            fp.write(json.dumps(lastLoginTime))
    except Exception:
        # e.g. insufficient write permissions, io error etc.
        log.err("Failed to write lastLoginTime to file \""+str(dbfilePath)+"\"")
