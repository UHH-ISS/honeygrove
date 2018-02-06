# coding=utf-8
import json
from datetime import datetime

from honeygrove import config
if config.use_broker:
    from honeygrove.broker import BrokerEndpoint

path = config.logpath
ID = str(config.HPID)
print_status = config.print_status
print_alerts = config.print_alerts
log_status = config.log_status
log_alerts = config.log_alerts

def write(message):
    """
    Simplify writing to logfile
    :param message: the message to be written
    """

    file = open(path, 'a')
    file.write(message)
    file.close()


def info(message):
    """
    Log function for administrative messages
    
    :param message: the message text
    """
    timestamp = datetime.utcnow().isoformat()

    message = '{} - [INFO] - {}\n'.format(timestamp, message)

    if log_status:
        write(message)
    
    if print_status:
        print(message)


def err(message):
    """
    Log function for exceptions
    :param message: the exception message
    """
    timestamp = datetime.utcnow().isoformat()

    message = '{} - [ERROR] - {}\n'.format(timestamp, message)

    if log_status:
        write(message)

    if print_status:
        print(message)


def defer_login(result, *args):
    """
    Wraps log.login for use with deferreds
    :param result: whatever
    :param args: arguments for login
    """
    login(*args)
    return result


def login(service, ip, port, successful, user, key=None, actual=None):
    """
    Log function to be called when someone attempts to login
    
    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param port: attackers port
    :param successful: boolean statin if the attempt was successful
    :param user: the username of the attempt
    :param key: the password or key of the attempt
    :param actual: the services where the login would have actually been valid (used for tracking honeytoken usage)
    """

    timestamp = datetime.utcnow().isoformat()

    message = ('{} - [LOGIN] - {}, {}, {}, {}, {}'.format(timestamp, service, ip, port, successful, user)
               + ((', ' + key) if key else ', ') + ((', ' + actual) if actual else ', ') + '\n')

    if not key:
        key = ""
    if not actual:
        actual = ""

    if successful:
        successful = "true"
    else:
        successful = "false"

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'login'}})
        bmessage = json.dumps(
            {'@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'successful': successful,
             'user': user, 'key': key, 'actual': actual, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)


def request(service, ip, port, request, user=None, request_type=None):
    """
    Log function to be called when a request is received
    
    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param port: attackers port
    :param request: the received request
    :param user: the user whose session invoked the alert
    :param request_type: for HTTP if the request is a GET or a POST request
    """
    timestamp = datetime.utcnow().isoformat()

    message = ('{} - [REQUEST] - {}, {}, {}'.format(timestamp, service, ip, request)
               + ((', ' + user) if user else ', ') + ((', ' + request_type) if request_type else ', ') + '\n')

    if not user:
        user = ""
    if not request_type:
        request_type = ""

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'request'}})
        bmessage = json.dumps(
            {'@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'request': request,
             'request_type': request_type, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)


def response(service, ip, port, response, user=None, statusCode=None):
    """
    Log function to be called when sending a response
    
    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param port: attackers port
    :param response: the response sent
    :param user: the user whose session invoked the alert
    :param statusCode: the status code send
    """
    timestamp = datetime.utcnow().isoformat()

    message = ('{} - [RESPONSE] - {}, {}, {}'.format(timestamp, service, ip, response)
               + ((', ' + user) if user else ', ') + ((', ' + statusCode) if statusCode else ', ') + '\n')

    if not user:
        user = ""
    if not statusCode:
        statusCode = ""

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'response'}})
        bmessage = json.dumps(
            {'@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'response': response,
             'request_type': statusCode, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_status:
        write(message)

    if print_status:
        print(message)


def file(service, ip, filename, filepath=None, user=None):
    """
    Log function to be called when receiving a file
    
    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param filename: name of the received file
    :param filepath: the path where the file was saved
    :param user: the user whose session invoked the alert 
    """

    timestamp = datetime.utcnow().isoformat()

    message = '{} - [FILE] - {}, {}, {}, {}\n'.format(timestamp, service, ip, filename, user)

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'file'}})
        bmessage = json.dumps({'@timestamp': timestamp, 'service': service, 'ip': ip, 'filename': filename, 'user': user, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if filepath and config.use_broker:  # Wenn kein Filepath übergeben wurde, wurde die Datei nicht gepeichert
        BrokerEndpoint.BrokerEndpoint.sendFile(filepath)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)


def tcp_syn(ip, port):
    """
    Log function to be called when a syn is received without a following ack
    :param ip: attacker's IP
    :param port: attacked port
    """

    timestamp = datetime.utcnow().isoformat()

    message = '{} - [SYN] - {}, {} + \n'.format(timestamp, ip, port)

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'syn'}})
        bmessage = json.dumps({'@timestamp': timestamp, 'ip': ip, 'port': port, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)


def limit_reached(service, ip):
    """
    Log function to be called when the maximum of connections per host for a service is reached
    
    :param service: the concerning service
    :param ip: attacker's IP-Address
    """
    timestamp = datetime.utcnow().isoformat()

    message = '{} - [LIMIT REACHED] - {}, {}\n'.format(timestamp, service, ip)

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'limit_reached'}})
        bmessage = json.dumps(
            {'@timestamp': timestamp, 'service': service, 'ip': ip, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)

def heartbeat():
    """
    Log function to be called when sending a heartbeat
    """
    timestamp = datetime.utcnow().isoformat()

    message = ('{} - [Heartbeat]'.format(timestamp) + '\n')

    if config.use_broker:
        bmessage_index = json.dumps({'index': {'_type': 'heartbeat'}})
        bmessage = json.dumps({'@timestamp': timestamp, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage_index)
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_status:
        write(message)

    if print_status:
        print(message)
