from pathlib import PurePath
import pickle


# Utility methods to pickle some config parts
def load_object(path):
    with open(str(path), 'rb') as f:
        return pickle.load(f)


def save_object(obj, path):
    with open(str(path), 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


# With this we get dot-notation for config subsections
class ConfigSection:
    pass


# Honeygrove configuration
class Config:

    # General configuration
    general = ConfigSection()
    general.id = "HG1"
    general.description = {"Name": str(general.id), "Location": "Hamburg, Germany", "Description": "Honeygrove instance #1"}
    general.address = "0.0.0.0"
    general.hostname = "euve256525"
    # Default maximum connections per host per service
    general.max_connections_per_host = 100
    # True = use UTC, False = use System Time
    general.use_utc = True
    # Set this to False if you do not want to use broker or broker is
    # unavailable on your machine. Currently, the management-console
    # and the EKStack can not be used without communication via Broker.
    general.use_broker = False
    # Set this to True if you want your output as parsable json format
    # for example to forward with logstash
    general.output_json = False
    # Set this to False if you do not want to use geoip or no database
    # is available on your machine.
    general.use_geoip = False
    # List of service names that should be enabled at startup
    # (defaults to all implemented services if letf empty)
    general.enabled_services = []

    # Logfile and output configuration
    logging = ConfigSection()
    # Status: Includes INFO-, HEARTBEAT-, RESPONSE- and ERROR-messages
    logging.print_status = True
    logging.print_alerts = True
    # Alerts: Includes LOGIN-, REQUEST-, FILE-, and SYN-messages
    logging.log_status = True
    logging.log_alerts = True

    # Folder configuration
    # All folder are relative to `folder.base`, so it is usually sufficient to only change this
    folder = ConfigSection()
    # Base path for resources and logs
    folder.base = PurePath('/var/honeygrove')
    # Resource related folders
    folder.resources = folder.base / 'resources'
    # Folder for emulated filesystem used by all services
    folder.filesystem = folder.resources / 'filesystem' / 'unix.xml'
    folder.honeytoken_files = folder.resources / 'honeytoken_files'
    folder.quarantine = folder.resources / 'quarantine'
    folder.tls = folder.resources / 'tls'
    if general.use_geoip:
        folder.geo_ip = folder.resources / 'geo_ip.db'
    # Log folder (currently only a single file)
    folder.log = folder.base / 'logs' / 'log.txt'

    # Ports without specific service
    listen = ConfigSection()
    listen.name = "LISTEN"
    listen.ports = [r for r in range(1, 5000)]
    tcp_scan = ConfigSection()
    tcp_scan.name = "TCP Scan Detector"
    tcp_scan.ports = [r for r in range(1, 5000)]
    # Timeframe in which ACK packets are expected to return
    # (to distinguish between port scans and valid connection attempts)
    tcp_scan.timeout = 5
    # Services which are not bound to a single port
    multiple_port_services = [listen.name, tcp_scan.name]

    # HTTP service configuration
    http = ConfigSection()
    http.name = "HTTP"
    http.port = 80
    http.connections_per_host = general.max_connections_per_host
    # Modify to simulate another server
    http.response_headers = {'Last-Modified': "Sun, 07 Aug 2019 08:02:22 GMT",
                             'Cache-Control': "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
                             'Pragma': "no-cache",
                             'Content-Type': "text/html; charset=UTF-8"}
    # To add your own HTML file you need to add it at httpSupportedSites
    # and add it into the dictionary below with its index. A
    # content page is optional. The first site is the login site, the
    # second one is the content page. The html login file needs
    # to have a login field with the name "log" and a password field
    # with the name of "pwd"
    http.resource_folder = folder.resources / 'http'
    http.html_dictionary_path = http.resource_folder / 'html_dictionary.pkl'
    http.html_dictionary_content = load_object(http.html_dictionary_path)

    def save_html_dictionary(self):
        save_object(self.http.html_dictionary_content, self.http.html_dictionary_path)

    # HTTPS service configuration
    https = ConfigSection()
    https.name = "HTTPS"
    https.port = 443
    https.connections_per_host = general.max_connections_per_host
    # TLS configuration
    https.tls_key = folder.tls / 'https.key'
    https.tls_cert = folder.tls / 'https.crt'

    # SSH service configuration
    ssh = ConfigSection()
    ssh.name = "SSH"
    ssh.port = 22
    ssh.connections_per_host = general.max_connections_per_host
    # must start with "SSH-2.0-"
    ssh.banner = b'SSH-2.0-' + general.hostname.encode()
    ssh.resource_folder = folder.resources / 'ssh'
    ssh.database_path = ssh.resource_folder / 'database.json'
    ssh.helptext_folder = ssh.resource_folder / 'helptexts'
    ssh.gnuhelp_folder = ssh.resource_folder / 'gnuhelp'
    ssh.real_shell = False
    ssh.accept_files = True
    ssh.accept_keys = False

    # Telnet service configuration
    telnet = ConfigSection()
    telnet.name = "Telnet"
    telnet.port = 23
    telnet.connections_per_host = general.max_connections_per_host
    # Currently not implemented
    telnet.real_shell = False

    # FTP service configuration
    ftp = ConfigSection()
    ftp.name = "FTP"
    ftp.port = 21
    ftp.connections_per_host = general.max_connections_per_host
    ftp.accept_files = True

    # Email (POP3(S), SMTP(S), IMAP(S)) related configuration
    email = ConfigSection()
    email.resource_folder = folder.resources / 'email'
    email.database_path = email.resource_folder / 'database.py'
    # TLS configuration
    email.tls_key = folder.tls / 'email.key'
    email.tls_cert = folder.tls / 'email.crt'

    # SMTP service configuration
    smtp = ConfigSection()
    smtp.name = "SMTP"
    smtp.port = 25
    smtp.connections_per_host = general.max_connections_per_host
    # CRAM-MD5 and SCRAM-SHA-1 aren't yet implemented! (using them anyway crashes the connection)
    smtp.authentication_methods = {"PLAIN": True, "LOGIN": True, "CRAM-MD5": False, "SCRAM-SHA-1": False}

    # SMTPS (SMTP + TLS) service configuration
    smtps = ConfigSection()
    smtps.name = "SMTPS"
    smtps.port = 587
    smtps.connections_per_host = general.max_connections_per_host

    # POP3 service configuration
    pop3 = ConfigSection()
    pop3.name = "POP3"
    pop3.port = 110
    pop3.connections_per_host = general.max_connections_per_host

    # POP3S (POP3 + TLS) service configuration
    pop3s = ConfigSection()
    pop3s.name = "POP3S"
    pop3s.port = 995
    pop3s.connections_per_host = general.max_connections_per_host

    # IMAP service configuration
    imap = ConfigSection()
    imap.name = "IMAP"
    imap.port = 143
    imap.connections_per_host = general.max_connections_per_host
    # CRAM-MD5 and SCRAM-SHA-1 aren't yet implemented! (using them anyway crashes the connection)
    imap.authentication_methods = smtp.authentication_methods

    # IMAPS (IMAP + TLS) service configuration
    imaps = ConfigSection()
    imaps.name = "IMAPS"
    imaps.port = 993
    imaps.connections_per_host = general.max_connections_per_host

    # Enable all known services if none are explicitly configured above
    if not general.enabled_services:
        general.enabled_services = [http.name, https.name, ssh.name, telnet.name, ftp.name, smtp.name,
                                    smtps.name, pop3.name, pop3s.name, imap.name, imaps.name,
                                    tcp_scan.name]

    # HoneytokenDB configuration
    honeytoken = ConfigSection()
    honeytoken.database_file = folder.resources / 'honeytokendb' / 'database.txt'
    honeytoken.generating = {"SSH": ["SSH", "FTP", "HTTP"], "HTTP": ["HTTP", "SSH"], "FTP": ["FTP"]}
    honeytoken.probabilities = {"SSH": 0.5, "FTP": 0.1, "HTTP": 0.9, "Telnet": 0.8}
    # True: password acceptance via hash, False: random acceptance
    honeytoken.accept_via_hash = True
    honeytoken.hash_seed = '__honeygrove__'
    # username length limits
    honeytoken.username_min = 6
    honeytoken.username_max = 24
    # password length limits
    honeytoken.password_min = 6
    honeytoken.password_max = 24

    # Optional: Broker configuration
    if (general.use_broker):
        broker = ConfigSection()
        # Optional: IP/port to listen on (e.g. for connections from the management console)
        broker.listen = False
        broker.listen_ip = '127.0.0.1'
        broker.listen_port = 8888

        # Optional: IP/port to peer to at startup (e.g. for connection to the CIM)
        broker.peer = False
        broker.peer_ip = '127.0.0.1'
        broker.peer_port = 34445

        # Optional: SSL Authentication
        broker.ssl_ca_file = None  # Path to CA file
        broker.ssl_ca_path = None  # Path to directory with CA files
        broker.ssl_certificate = None  # Own certificate
        broker.ssl_key_file = None  # Own key
