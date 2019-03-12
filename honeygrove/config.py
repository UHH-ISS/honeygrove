from pathlib import PurePath
import pickle


# Utility methods to pickle some config parts
def load_object(path):
    with open(path, 'rb') as f:
        return pickle.load(f)


def save_object(obj, path):
    with open(path, 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


# With this we get dot-notation for config subsections
class ConfigSection:
    pass


# Honeygrove configuration
class Config:

    # General configuration
    HPID = "HP1"
    machine_name = "hp1"
    hp_description = {"Name": str(HPID), "Location": "Moscow, Russia", "Description": "Honeygrove instance"}
    # Set this to False if you do not want to use broker or broker is
    # unavailable on your machine. Currently, the management-console
    # and the EKStack can not be used without communication via Broker.
    use_broker = False

    # Set this to False if you do not want to use geoip or no database
    # is available on your machine.
    use_geoip = False

    # Logfile and output configuration
    # Status: Inlcudes INFO-, HEARTBEAT-, RESPONSE- and ERROR-messages
    # Alerts: Inlcudes LOGIN-, REQUEST-, FILE-, and SYN-messages
    print_status = True
    print_alerts = True
    log_status = True
    log_alerts = True
    # True = use UTC, False = use System Time
    use_utc = True

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
    if use_geoip:
        folder.geo_ip = folder.resources / 'geo_ip.db'
    # Log folder (currently only a single file)
    folder.log = folder.base / 'logs' / 'log.txt'

    # Ports without sepcific service
    listenServicePorts = [r for r in range(1, 5000)]
    listenServiceName = "LISTEN"
    tcpFlagSnifferName = "TCPFlagSniffer"

    # Default maximum connections per host per service
    max_connections_per_host = 100

    # HTTP service configuration
    http = ConfigSection()
    http.name = "HTTP"
    http.port = 80
    # Modify to simulate another server
    http.response_headers = {'Last-Modified': "Sun, 07 Aug 2016 08:02:22 GMT",
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

    # SSH service configuration
    ssh = ConfigSection()
    ssh.name = "SSH"
    ssh.port = 22
    # must start with "SSH-2.0-"
    ssh.banner = b'SSH-2.0-uhh'
    ssh.resource_folder = folder.resources / 'ssh'
    ssh.resource_database = ssh.resource_folder / 'database.json'
    ssh.helptext_folder = ssh.resource_folder / 'helptexts'
    ssh.gnuhelp_folder = ssh.resource_folder / 'gnuhelp'
    ssh.real_shell = False
    ssh.accept_files = True
    ssh.connections_per_host = max_connections_per_host

    # Telnet service configuration
    telnet = ConfigSection()
    telnet.name = "Telnet"
    telnet.port = 23
    # Currently not implemented
    telnet.real_shell = False
    telnet.connections_per_host = max_connections_per_host

    # FTP service configuration
    ftp = ConfigSection()
    ftp.name = "FTP"
    ftp.port = 21
    ftp.accept_files = True
    ftp.connections_per_host = max_connections_per_host

    # Email (POP3(S), SMTP(S), IMAP(S)) related configuration
    email = ConfigSection()
    # TLS configuration
    email.tls_key = folder.tls / 'email.key'
    email.tls_cert = folder.tls / 'email.crt'

    # SMTP service configuration
    smtp = ConfigSection()
    smtp.name = "SMTP"
    smtp.port = 25
    # CRAM-MD5 and SCRAM-SHA-1 aren't yet implemented! (using them anyway crashes the connection)
    smtp.authentication_methods = {"PLAIN": True, "LOGIN": True, "CRAM-MD5": False, "SCRAM-SHA-1": False}
    smtp.connections_per_host = max_connections_per_host

    # SMTPS (SMTP + TLS) service configuration
    smtps = ConfigSection()
    smtps.name = "SMTPS"
    smtps.port = 587
    smtps.connections_per_host = max_connections_per_host

    # POP3 service configuration
    pop3 = ConfigSection()
    pop3.name = "POP3"
    pop3.port = 110
    pop3.connections_per_host = max_connections_per_host

    # POP3S (POP3 + TLS) service configuration
    pop3s = ConfigSection()
    pop3s.name = "POP3S"
    pop3s.port = 995
    pop3s.connections_per_host = max_connections_per_host

    # IMAP service configuration
    imap = ConfigSection()
    imap.name = "IMAP"
    imap.port = 143
    # CRAM-MD5 and SCRAM-SHA-1 aren't yet implemented! (using them anyway crashes the connection)
    imap.authentication_methods = smtp.authentication_methods
    imap.connections_per_host = max_connections_per_host

    # IMAPS (IMAP + TLS) service configuration
    imaps = ConfigSection()
    imaps.name = "IMAPS"
    imaps.port = 993
    imaps.connections_per_host = max_connections_per_host

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

    # List of service names that should be enabled at startup
    # Defaults to all implemented services
    enabled_services = [http.name, ssh.name, telnet.name, ftp.name, smtp.name, smtps.name, pop3.name, pop3s.name, imap.name, imaps.name, tcpFlagSnifferName]

    # Services which are not bound to a single port
    noPortSpecificService = [listenServiceName, tcpFlagSnifferName]

    # Zeitraum, in welchen ein ACK-Paket beim Verbindungsaufbau zurückkommen soll
    # (Timeout zur Unterscheidung von Scans gegenüber einem ernsthaften Verbindungsaufbau)
    tcpTimeout = 5

    # Optional: Broker configuration
    if (use_broker):
        broker = ConfigSection()
        # Optional: IP/port to listen on (e.g. for connections from the management console)
        broker.listen = False
        broker.listen_ip = '127.0.0.1'
        broker.listen_port = 8888

        # Optional: IP/port to peer to at startup (e.g. for connection to the CIM)
        broker.peer = False
        broker.peer_ip = '127.0.0.1'
        broker.peer_port = 34445
