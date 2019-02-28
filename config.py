import honeygrove
import socket
from honeygrove.resources.http_resources import HTMLLoader


# With this we get dot-notation for config subsections
class ConfigSection:
    pass


# Honeygrove configuration
class Config:
    # Generic
    HPID = "HP1"
    machine_name = "hp1"
    hp_description = {"Name": str(HPID), "Location": "Moscow, Russia", "Description": "Honeygrove instance"}
    base_dir = honeygrove.__path__[0] + "/"
    resources_dir = base_dir + "resources/"
    logpath = resources_dir + "logfile/log.txt"
    geodatabasepath = resources_dir + "/path/to/database"

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

    # Generic configuration:
    listenServicePorts = [r for r in range(1, 5000)]
    listenServiceName = "LISTEN"
    tcpFlagSnifferName = "TCPFlagSniffer"

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
    http.html_dictionary = HTMLLoader.load_HTMLDictionary()
    http.resource_folder = resources_dir + "/http_resources/"

    # SSH service configuration
    ssh = ConfigSection()
    ssh.name = "SSH"
    ssh.port = 22
    # must start with "SSH-2.0-"
    ssh.banner = b'SSH-2.0-uhh'
    ssh.helptext_folder = resources_dir + "ssh_resources/helptexts"
    ssh.gnuhelp_folder = resources_dir + "ssh_resources/gnuhelp"
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
    email.tls_key = base_dir + "keys/server.key"
    email.tls_cert = base_dir + "keys/server.crt"

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

    # Path to Filesystem all services are using
    path_to_filesys = resources_dir + '/parser_resources' + '/unix.xml'

    # Honeytoken Directory
    tokendir = resources_dir + '/honeytokenfiles'

    # HoneytokenDB configuration:
    tokenDatabase = resources_dir + "/honeytokendb/database.txt"
    honeytokendbGenerating = {"SSH": ["SSH", "FTP", "HTTP"], "HTTP": ["HTTP", "SSH"], "FTP": ["FTP"]}
    honeytokendbProbabilities = {"SSH": 0.5, "FTP": 0.1, "HTTP": 0.9, "Telnet": 0.8}
    # hashAccept True: password acceptance over hash, False: random acceptance
    hashAccept = True
    hashSeed = b'Honey'

    # password criteria
    pc_minLength = 6
    pc_maxLength = 24

    # username criteria
    nc_minLength = 6
    nc_maxLength = 24

    # Malware configuration
    quarantineDir = resources_dir + "/quarantine"

    # List of service names that should be enabled at startup
    # Defaults to all implemented services
    startupList = [http.name, ssh.name, telnet.name, ftp.name, smtp.name, smtps.name, pop3.name, pop3s.name, imap.name, imaps.name, tcpFlagSnifferName]

    # Services which are not bound to a single port
    noPortSpecificService = [listenServiceName, tcpFlagSnifferName]

    # Zeitraum, in welchen ein ACK-Paket beim Verbindungsaufbau zurückkommen soll
    # (Timeout zur Unterscheidung von Scans gegenüber einem ernsthaften Verbindungsaufbau)
    tcpTimeout = 5

    # Broker Config
    def get_ip_address():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    # Needed for Broker to listen on correct IP - change "ip_addr" (string) for custom IP
    if (use_broker):
        ip_addr = get_ip_address()
        BrokerComIP = ip_addr
        BrokerComPort = 8888

    # Opt. initial peering
    init_peer = False
    init_peer_ip = ""
    init_peer_port = 34445

    # HoneyAdapter: StartMode
    honeygrove_start = 'active'
