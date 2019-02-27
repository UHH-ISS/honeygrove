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
    ssh.connections_per_host = 100

    # Telnet service configuration
    telnet = ConfigSection()
    telnet.name = "Telnet"
    telnet.port = 23
    # Currently not implemented
    telnet.real_shell = False
    telnet.connections_per_host = 100

    # FTP configuration:
    ftpPort = 21
    ftpName = "FTP"
    FTP_conn_per_host = 100

    # TLS server certificate used for email services
    TLSeMailKey = base_dir + "keys/server.key"
    TLSeMailCrt = base_dir + "keys/server.crt"

    # SMTP configuration:
    smtpPort = 25
    smtpName = "SMTP"
    SMTP_conn_per_host = 100

    # SMTPS (SMTP + TLS) configuration:
    smtpsPort = 587
    smtpsName = "SMTPS"
    SMTPS_conn_per_host = 100

    # CRAM-MD5 and SCRAM-SHA-1 aren't yet implemented! (using them anyway crashes the connection)
    SMTPAuthMethods = {"PLAIN": True, "LOGIN": True, "CRAM-MD5": False, "SCRAM-SHA-1": False}

    # POP3 configuration:
    pop3Port = 110
    pop3Name = "POP3"
    POP3_conn_per_host = 100

    # POP3S (POP3 + TLS) configuration:
    pop3sPort = 995
    pop3sName = "POP3S"
    POP3S_conn_per_host = 100

    # IMAP configuration:
    imapPort = 143
    imapName = "IMAP"
    IMAP_conn_per_host = 100

    # IMAPS (IMAP + TLS) configuration:
    imapsPort = 993
    imapsName = "IMAPS"
    IMAPS_conn_per_host = 100

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
    ftpAcceptsFiles = True
    quarantineDir = resources_dir + "/quarantine"

    # Startup
    startupList = [http.name, ssh.name, telnet.name, ftpName, tcpFlagSnifferName, smtpName, smtpsName, pop3Name, pop3sName, imapName, imapsName]

    # Services, die nicht an einen Port gebunden sind
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
