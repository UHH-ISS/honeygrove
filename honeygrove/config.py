import uuid
import honeygrove
import socket
from honeygrove.resources.http_resources import HTMLLoader

# Honeypot service configuration file
HPID = "HP1"
machine_name = "hp1"
hp_description = {"Ort" : "Moskau", "Name" : str(HPID), "Text" : "Special Honeypot 007"}
resources = honeygrove.__path__._path[0] + "/resources"
logpath = resources + "/logfile/log.txt"

# Logfile and output configuration
# Status: Inlcudes INFO-, HEARTBEAT-, RESPONSE- and ERROR-messages
# Alerts: Inlcudes LOGIN-, REQUEST-, FILE-, and SYN-messages
print_status = True
print_alerts = True
log_status = True
log_alerts = True


# Generic configuration:
listenServicePorts = [r for r in range(1, 5000)]
listenServiceName = "LISTEN"
tcpFlagSnifferName = "TCPFlagSniffer"


# Modify to simulate another server
httpResponseHeader = {'Last-Modified': "Sun, 07 Aug 2016 08:02:22 GMT",
                      'Cache-Control': "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
                      'Pragma': "no-cache",
                      'Content-Type': "text/html; charset=UTF-8"}

# To add your own HTML file you need to add it at httpSupportedSites
# and add it into the dictionary below with its index. A
# content page is optional. The first site is the login site, the
# second one is the content page. The html login file needs
# to have a login field with the name "log" and a password field
# with the name of "pwd"
httpHTMLDictionary = HTMLLoader.load_HTMLDictionary()
httpResources = resources + "/http_resources/"

# HTTP configuration:
httpPort = 80
httpName = "HTTP"

# SSH configuration:
sshPort = 22
sshName = "SSH"
ssh_real_shell = False

# FTP configuration:
ftpPort = 21
ftpName = "FTP"

# Path to Filesystem all services are using
path_to_filesys = resources + '/parser_resources' +'/unix.xml'


# Honeytoken Directory
tokendir = resources + '/honeytokenfiles'

# HoneytokenDB configuration:
tokenDatabase = resources + "/honeytokendb/database.txt"
honeytokendbGenerating = {"SSH": ["SSH", "FTP", "HTTP"], "HTTP": ["HTTP", "SSH"], "FTP": ["FTP"]}
honeytokendbProbabilities = {"SSH": 0.5, "FTP": 0.1, "HTTP": 0.9, "Telnet": 0.8}


# Malware configuration
sshAcceptsFiles = True
ftpAcceptsFiles = True
quarantineDir = honeygrove.__path__._path[0] + "/resources/quarantine"


# Startup
startupList = [httpName, ftpName, sshName, tcpFlagSnifferName]

# Services die nicht an einen Port gebunden sind
noPortSpecificService = [listenServiceName, tcpFlagSnifferName]

# Zeitraum in der ein ACK packet nach ACK - SYN zurückommen soll
tcpTimeout = 5


# Broker Config
def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# Needed that Broker listens on right IP
# change ip_addr (str) for custom ip
ip_addr = get_ip_address()
BrokerComIP = ip_addr
BrokerComPort = 8888

# HoneyAdapter: StartMode
honeygrove_start = 'active'
