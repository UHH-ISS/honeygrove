# coding=utf-8
import json
from datetime import datetime

from honeygrove import config
if config.use_broker:
    from honeygrove.broker import BrokerEndpoint
if config.use_geoip:
    import geoip2.database

path = config.logpath
geodatabasepath = config.geodatabasepath
ID = str(config.HPID)
print_status = config.print_status
print_alerts = config.print_alerts
log_status = config.log_status
log_alerts = config.log_alerts

if config.use_geoip:
    reader = geoip2.database.Reader(geodatabasepath)

def write(message):
    """
    Simplify writing to logfile
    :param message: the message to be written
    """

    file = open(path, 'a')
    file.write(message)
    file.close()

def get_coordinates(ipaddress):
    """
    Gets the Location Information for given IP Address
    from Location Database. Returns False if location
    lookup is disabled

    :param ipaddress: the address out of a log entry
    """

    if config.use_geoip:
        response = reader.city(ipaddress)
        lat = float(response.location.latitude)
        lon = float(response.location.longitude)
        return [lat, lon]
    else:
        return False

def get_time():
    if config.use_utc:
        return datetime.utcnow()
    else:
        return datetime.now()


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

    coordinates = get_coordinates(ip)

    if not key:
        key = ""
    if not actual:
        actual = ""

    if coordinates:
        message = '{} - [LOGIN] - {}, {}, Latitude: {:.4f}, Longitude: {:.4f}, {}, {}, {}, {}, {}\n'.format(timestamp, service, ip, coordinates[0], coordinates[1], port, successful, user, key, actual)

    else:
        message = '{} - [LOGIN] - {}, {}, {}, {}, {}, {}, {}\n'.format(timestamp, service, ip, port, successful, user, key, actual)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': 'login', '@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'successful': str(successful), 'user': user, 'key': key, 'actual': actual, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})

        else:
            bmessage = json.dumps({'event_type': 'login', '@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'successful': str(successful), 'user': user, 'key': key, 'actual': actual, 'honeypotID': ID})

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

    coordinates = get_coordinates(ip)

    if not user:
        user = ""
    if not request_type:
        request_type = ""

    if coordinates:
        message = '{} - [REQUEST] - {}, {}, Latitude: {:.4f}, Longitude: {:.4f}, {}, {}, {}\n'.format(timestamp, service, ip, coordinates[0], coordinates[1], request, user, request_type)

    else:
        message = '{} - [REQUEST] - {}, {}, {}, {}, {}\n'.format(timestamp, service, ip, request, user, request_type)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': 'request', '@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'request': request, 'request_type': request_type, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})

        else:
            bmessage = json.dumps({'event_type': 'request','@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'request': request, 'request_type': request_type, 'honeypotID': ID})

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

    if not user:
        user = ""
    if not statusCode:
        statusCode = ""

    coordinates = get_coordinates(ip)

    if coordinates:
        message = '{} - [RESPONSE] - {}, {}, Latitude: {:.4f}, Longitude: {:.4f}, {}, {}, {}\n'.format(timestamp, service, ip, coordinates[0], coordinates[1], response, user, statusCode)

    else:
        message = '{} - [RESPONSE] - {}, {}, {}, {}, {}\n'.format(timestamp, service, ip, response, user, statusCode)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': 'response', '@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'response': response, 'request_type': statusCode, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})
        else:
            bmessage = json.dumps({'event_type': 'response', '@timestamp': timestamp, 'service': service, 'ip': ip, 'port': str(port), 'user': user, 'response': response, 'request_type': statusCode, 'honeypotID': ID})

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

    coordinates = get_coordinates(ip)

    if coordinates:
        message = '{} - [FILE] - {}, {}, Latitude: {:.4f}, Longitude: {:.4f}, {}, {}\n'.format(timestamp, service, ip, coordinates[0], coordinates[1], filename, user)

    else:
        message = '{} - [FILE] - {}, {}, {}, {}\n'.format(timestamp, service, ip, filename, user)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': 'file', '@timestamp': timestamp, 'service': service, 'ip': ip, 'filename': filename, 'user': user, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})

        else:
            bmessage = json.dumps({'event_type': 'file', '@timestamp': timestamp, 'service': service, 'ip': ip, 'filename': filename, 'user': user, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if filepath and config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendFile(filepath)

    if log_alerts:
        write(message)

    if print_alerts:
        print(message)


def tcp_scan(ip, port, intime, scan_type):
    """
    Log function to be called when a scan is detected
    :param ip: attacker's IP
    :param port: attacked port
    :param time: time of attack
    """

    timestamp = datetime.utcnow().isoformat()

    coordinates = get_coordinates(ip)

    if coordinates:
        message = '{} - [{}-scan] - {}, Latitude: {:.4f}, Longitude: {:.4f}, {}\n'.format(timestamp, scan_type, ip, coordinates[0], coordinates[1], port)

    else:
        message = '{} - [{}-scan] - {}, {}\n'.format(timestamp, scan_type, ip, port)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': scan_type, '@timestamp': timestamp, 'ip': ip, 'port': port, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})

        else:
            bmessage = json.dumps({'event_type': scan_type, '@timestamp': timestamp, 'ip': ip, 'port': port, 'honeypotID': ID})

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

    coordinates = get_coordinates(ip)

    if coordinates:
        message = '{} - [LIMIT REACHED] - {}, {}, Latitude: {:.4f}, Longitude: {:.4f}\n'.format(timestamp, service, ip, coordinates[0], coordinates[1])

    else:
        message = '{} - [LIMIT REACHED] - {}, {}\n'.format(timestamp, service, ip)

    if config.use_broker:
        if coordinates:
            bmessage = json.dumps({'event_type': 'limit_reached', '@timestamp': timestamp, 'service': service, 'ip': ip, 'coordinates': '{:.4f},{:.4f}'.format(coordinates[0], coordinates[1]), 'honeypotID': ID})

        else:
            bmessage = json.dumps({'event_type': 'limit_reached', '@timestamp': timestamp, 'service': service, 'ip': ip, 'honeypotID': ID})

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
        bmessage = json.dumps({'event_type': 'heartbeat', '@timestamp': timestamp, 'honeypotID': ID})

        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    if log_status:
        write(message)

    if print_status:
        print(message)
