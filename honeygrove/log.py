from honeygrove.config import Config

from collections import defaultdict
from datetime import datetime
import json

if Config.use_broker:
    from honeygrove.broker import BrokerEndpoint
if Config.use_geoip:
    import geoip2.database

# Honeypot ID
ID = str(Config.HPID)

# Folders
path = Config.folder.log
if Config.use_geoip:
    geodatabasepath = Config.folder.geo_ip

# Settings
print_status = Config.print_status
print_alerts = Config.print_alerts
log_status = Config.log_status
log_alerts = Config.log_alerts

if Config.use_geoip:
    try:
        reader = geoip2.database.Reader(geodatabasepath)
    except FileNotFoundError:
        print("\nGeoIP database file not found, disabled GeoIP!\n")
        Config.use_geoip = False

PLACEHOLDER_STRING = '--'


def _log_status(message):
    if log_status:
        write(message + '\n')
    if print_status:
        print(message)


def _log_alert(message):
    if log_alerts:
        write(message + '\n')
    if print_alerts:
        print(message)


def write(message):
    """
    Simplify writing to logfile
    :param message: the message to be written
    """

    with open(str(path), 'a') as fp:
        fp.write(message)


def get_coordinates(ipaddress):
    """
    Gets the Location Information for given IP Address
    from Location Database. Returns False if location
    lookup is disabled

    :param ipaddress: the address out of a log entry
    """

    if Config.use_geoip:
        response = reader.city(ipaddress)
        lat = float(response.location.latitude)
        lon = float(response.location.longitude)
        return [lat, lon]
    else:
        return False


def get_time():
    if Config.use_utc:
        return datetime.utcnow()
    else:
        return datetime.now()


def format_time(intime):
    return intime.isoformat()


def info(message):
    """
    Log function for administrative messages

    :param message: the message text
    """

    timestamp = format_time(get_time())
    message = '{} - [INFO] - {}'.format(timestamp, message)
    _log_status(message)


def err(message):
    """
    Log function for exceptions

    :param message: the exception message
    """

    timestamp = format_time(get_time())
    message = '{} - [ERROR] - {}'.format(timestamp, message)
    _log_status(message)


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

    timestamp = format_time(get_time())
    coordinates = get_coordinates(ip)

    if not key:
        key = PLACEHOLDER_STRING
    if not actual:
        actual = PLACEHOLDER_STRING

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': 'login',
                          '@timestamp': timestamp,
                          'service': service,
                          'ip': ip,
                          'port': str(port),
                          'successful': str(successful),
                          'user': user,
                          'key': key,
                          'actual': actual,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))

    message = ('{@timestamp} - [LOGIN] - {service}, {ip}:{port}, Lat: {lat}, Lon: {lon}, '
               '{successful}, {user}, {key}, {actual}').format_map(values)
    _log_alert(message)


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

    timestamp = format_time(get_time())
    coordinates = get_coordinates(ip)

    if not user:
        user = PLACEHOLDER_STRING
    if not request_type:
        request_type = PLACEHOLDER_STRING

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': 'request',
                          '@timestamp': timestamp,
                          'service': service,
                          'ip': ip,
                          'port': port,
                          'user': user,
                          'request': request,
                          'request_type': request_type,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))

    message = ('{@timestamp} - [REQUEST] - {service}, {ip}:{port}, Lat: {lat}, Lon: {lon}, '
               '{request}, {user}, {request_type}').format_map(values)
    _log_alert(message)


def response(service, ip, port, response, user=None, status_code=None):
    """
    Log function to be called when sending a response

    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param port: attackers port
    :param response: the response sent
    :param user: the user whose session invoked the alert
    :param statusCode: the status code send
    """

    timestamp = format_time(get_time())
    coordinates = get_coordinates(ip)

    if not user:
        user = PLACEHOLDER_STRING
    if not status_code:
        status_code = PLACEHOLDER_STRING

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': 'response',
                          '@timestamp': timestamp,
                          'service': service,
                          'ip': ip,
                          'port': port,
                          'user': user,
                          'response': response,
                          'request_type': status_code,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))

    message = ('{@timestamp} - [RESPONSE] - {service}, {ip}:{port}, Lat: {lat}, Lon: {lon}, '
               '{response}, {user}, {request_type}').format_map(values)
    _log_alert(message)


def file(service, ip, file_name, file_path=None, user=None):
    """
    Log function to be called when receiving a file

    :param service: the concerning service
    :param ip: attacker's IP-Address
    :param filename: name of the received file
    :param filepath: the path where the file was saved
    :param user: the user whose session invoked the alert
    """

    timestamp = format_time(get_time())
    coordinates = get_coordinates(ip)

    if not file_path:
        file_path = PLACEHOLDER_STRING
    if not user:
        user = PLACEHOLDER_STRING

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': 'file',
                          '@timestamp': timestamp,
                          'service': service,
                          'ip': ip,
                          'user': user,
                          'filename': file_name,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))
        if file_path:
            BrokerEndpoint.BrokerEndpoint.sendFile(file_path)

    message = '{@timestamp} - [FILE] - {service}, {ip}, Lat: {lat}, Lon: {lon}, {filename}, {user}'.format_map(values)
    _log_alert(message)


def scan(ip, port, intime, scan_type):
    """
    Log function to be called when a scan is detected

    :param ip: attacker's IP
    :param port: attacked port
    :param time: time of attack
    """

    timestamp = format_time(intime)
    coordinates = get_coordinates(ip)

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': '{}-scan'.format(scan_type),
                          '@timestamp': timestamp,
                          'ip': ip,
                          'port': port,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))

    message = '{@timestamp} - [{}-SCAN] - {ip}:{port}, Lat: {lat}, Lon: {lon}'.format_map(values)
    _log_alert(message)


def limit_reached(service, ip):
    """
    Log function to be called when the maximum of connections per host for a service is reached

    :param service: the concerning service
    :param ip: attacker's IP-Address
    """

    timestamp = format_time(get_time())
    coordinates = get_coordinates(ip)

    values = defaultdict(lambda: PLACEHOLDER_STRING,
                         {'event_type': 'limit_reached',
                          '@timestamp': timestamp,
                          'service': service,
                          'ip': ip,
                          'honeypotID': ID})

    if coordinates:
        values['lat'] = '{:.4f}'.format(coordinates[0])
        values['lon'] = '{:.4f}'.format(coordinates[1])

    if Config.use_broker:
        BrokerEndpoint.BrokerEndpoint.sendLogs(json.dumps(values))

    message = '{@timestamp} - [LIMIT REACHED] - {service}, {ip}, Lat: {lat}, Lon: {lon}'.format_map(values)
    _log_alert(message)


def heartbeat():
    """
    Log function to be called when sending a heartbeat
    """

    timestamp = format_time(get_time())

    if Config.use_broker:
        bmessage = json.dumps({'event_type': 'heartbeat', '@timestamp': timestamp, 'honeypotID': ID})
        BrokerEndpoint.BrokerEndpoint.sendLogs(bmessage)

    message = ('{} - [Heartbeat]'.format(timestamp))
    _log_status(message)
