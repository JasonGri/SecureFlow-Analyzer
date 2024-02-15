CHART_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']

PROTOCOL_NUMS = {
    1: "ICMP",
    0: "IP",
    2: "IGMP",
    4: "IPIP",
    6: "TCP",
    8: "EGP",
    9: "IGP",
    17: "UDP",
    58: "IPv6-ICMP",
    41: "IPv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    88: "EIGRP",
    89: "OSPFIGP",
    94: "IPIP",
    97: "EtherIP",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    118: "STP",
    121: "SMP",
    124: "PIPE",
    132: "SCTP",
    133: "FC",
    137: "MPLS",
    138: "MPLS-MCAST",
    139: "UDPLite",
    140: "MPLS-UDPLite",
    142: "MP",
    254: "RAW"
}

PAPER_BG_COLOR = '#aab8ff'

PLOT_BG_COLOR = '#cad7ff'

CHART_FONT_COLOR = '#1d2454'


VULN_PORT_NUMS = {
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    992: 'telnets',
    107: 'rtelnet',
    69: 'tftp',
    3389: 'ms-wbt-server',
    5900: 'vnc',
    5901: 'vnc-1',
    5902: 'vnc-2',
    512: 'exec',
    513: 'login',
    514: 'cmd',
    873: 'rsync',
    111: 'sunrpc',
    2049: 'nfsd',
    135: 'epmap',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    445: 'microsoft-ds',
    161: 'snmp',
    389: 'ldap',
    25: 'smtp',
    109: 'pop2',
    110: 'pop3',
    143: 'imap',
    80: 'http',
    8000: 'http',
    8080: 'http',
    8888: 'http',
    1433: 'ms-sql-s',
    1521: 'oracle-db',
    3306: 'mysql-db',
    5000: 'UPnP',
    5432: 'postgreSQL-db',
    6379: 'redis-db',
    27017: 'mongodb',
    27018: 'mongodb'
}

MALICIOUS_DOMAINS_URL = 'https://hole.cert.pl/domains/domains_hosts.txt'

MALICIOUS_IP_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt'

MALICIOUS_IPV6_URL = 'https://www.spamhaus.org/drop/dropv6.txt'
