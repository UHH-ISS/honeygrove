# Unsere Tests sollten nichts an das Logging schicken.
# Daher gibt es dieses Fake-Logging, dass die Protokolle im Test
# als Logging-Ersatz nutzen können


def attack(service, ip, request, response, user=None, key=None):
    pass

def file(service, ip, filename, file, user=None):
    pass

def login(service, ip, port, successful, user, key=None, actual=None):
    pass

def request(service, ip, port, request, user=None, request_type=None):
    pass

def response(service, ip, port, response, user=None, statusCode=None):
    pass
