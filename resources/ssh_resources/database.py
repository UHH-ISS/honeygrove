import json
from honeygrove import config
from honeygrove.logging import log    
dbfilePath = config.resources_dir + "ssh_resources/database.json"

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
        except:
            # e.g. damaged json encoding
            log.err("Failed to load lastLoginTime from existing file \""+str(dbfilePath)+"\"")


def save():
    try:
        file = open(dbfilePath, 'w')
        file.write(json.dumps(lastLoginTime))
        file.close()
    except:
        # e.g. insufficient write permissions, io error etc.
        log.err("Failed to write lastLoginTime to file \""+str(dbfilePath)+"\"")