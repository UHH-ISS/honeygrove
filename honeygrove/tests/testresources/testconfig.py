from honeygrove.tests.testresources import __path__ as resources

import uuid

# HoneytokenDB configuration:
honeytokendbProbabilities = {"TESTSERVICEA": 0.5, "TESTSERVICEB": 0.1, "LISTEN": 0.1}
HPID = str(uuid.uuid4())

# Path to Filesystem all services are using
path_to_filesys = resources._path[0] + '/test_filesys.xml'

# Honeytoken Directory
tokendir = 'testresources/honeytokenfiles'


sshPort = 12222
sshName = "SSH"
resources = 'testresources'

# Honeyadaptertest
tokendir_adapter = 'testresources/honeyadaptertest/tokens'
