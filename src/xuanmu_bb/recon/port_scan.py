"""端口扫描工具 — 基于 asyncio TCP Connect"""

import asyncio
import socket
from typing import Optional

from ..utils import parse_ports


# 常见端口 - 服务映射
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-ALT", 88: "Kerberos", 110: "POP3",
    111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IPSec", 502: "Modbus", 512: "rexec",
    513: "rlogin", 514: "syslog", 523: "OpenVPN", 548: "AFP",
    554: "RTSP", 587: "SMTP-Submit", 623: "IPMI", 636: "LDAPS",
    873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS5", 1099: "RMI", 1194: "OpenVPN", 1241: "Nessus",
    1352: "Lotus", 1433: "MSSQL", 1434: "MSSQL-UDPM", 1521: "Oracle",
    1526: "Oracle-ALT", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2100: "Oracle-XDB", 2222: "SSH-ALT",
    2375: "Docker", 2376: "Docker-TLS", 2424: "OrientDB", 2443: "HTTPS-ALT",
    2483: "Oracle-SSL", 2484: "Oracle-SSL-ALT", 3000: "Gitea/Node",
    3128: "Squid", 3306: "MySQL", 3312: "Kangle", 3389: "RDP",
    3443: "HTTPS-ALT", 3690: "SVN", 4000: "Node", 4040: "Tomcat",
    4222: "SSH-ALT", 4243: "Docker", 4444: "Metasploit", 4445: "Metasploit",
    4560: "Logstash", 4567: "Sinatra", 4711: "Jenkins", 4848: "GlassFish",
    4899: "RAdmin", 5000: "Flask/Node", 5001: "Flask/Node", 5002: "Flask/Node",
    5005: "Java-Remote-Debug", 5006: "Java-Remote-Debug", 5007: "Java-Remote-Debug",
    5038: "Asterisk", 5060: "SIP", 5061: "SIPS", 5222: "XMPP",
    5269: "XMPP-S2S", 5432: "PostgreSQL", 5555: "Android-ADB",
    5601: "Kibana", 5634: "SSH-ALT", 5672: "AMQP", 5800: "VNC-HTTP",
    5900: "VNC", 5901: "VNC-1", 6000: "X11", 6001: "X11-1",
    6082: "Varnish", 6161: "JMX", 6379: "Redis", 6443: "Kubernetes",
    6588: "Tomcat", 7001: "WebLogic", 7002: "WebLogic-SSL",
    7070: "WebSphere", 7071: "WebSphere", 7077: "Spark", 7199: "Cassandra",
    7210: "MaxDB", 7443: "HTTPS-ALT", 7474: "Neo4j", 7547: "CWMP",
    7634: "MySQL-ALT", 7777: "LiteSpeed", 8000: "HTTP-ALT", 8001: "HTTP-ALT",
    8005: "Tomcat-Shutdown", 8008: "HTTP-ALT", 8009: "AJP", 8010: "HTTP-ALT",
    8040: "HTTP-ALT", 8042: "HTTP-ALT", 8060: "HTTP-ALT", 8069: "Odoo",
    8080: "HTTP-Proxy", 8081: "HTTP-Proxy", 8082: "HTTP-Proxy",
    8083: "HTTP-Proxy", 8084: "HTTP-Proxy", 8085: "HTTP-Proxy",
    8086: "InfluxDB", 8087: "HTTP-Proxy", 8088: "HTTP-Proxy",
    8089: "Splunk", 8090: "HTTP-Proxy", 8091: "Couchbase",
    8092: "Couchbase", 8093: "Couchbase", 8096: "Emby",
    8100: "HTTP-ALT", 8125: "StatsD", 8161: "ActiveMQ",
    8200: "Docker-Registry", 8222: "VMWare", 8243: "HTTPS-ALT",
    8280: "HTTP-ALT", 8300: "Consul", 8400: "HTTP-ALT",
    8443: "HTTPS-ALT", 8530: "HTTP-ALT", 8531: "HTTPS-ALT",
    8649: "Ganglia", 8686: "JMX", 8787: "Java-Debug",
    8800: "HTTP-ALT", 8834: "Nessus", 8843: "HTTPS-ALT",
    8880: "HTTP-ALT", 8888: "HTTP-ALT", 8889: "HTTP-ALT",
    8983: "Solr", 8990: "HTTP-ALT", 8991: "HTTP-ALT", 9000: "Node",
    9001: "Node", 9009: "WebLogic", 9042: "Cassandra-CQL",
    9050: "Tor", 9060: "WebSphere", 9080: "WebSphere",
    9081: "WebSphere", 9090: "HTTP-ALT", 9091: "HTTP-ALT",
    9092: "Kafka", 9093: "Kafka-SSL", 9094: "Kafka", 9100: "Jetty",
    9119: "MX4J", 9160: "Cassandra-Thrift", 9191: "KairosDB",
    9200: "Elasticsearch", 9300: "Elasticsearch", 9418: "Git",
    9443: "HTTPS-ALT", 9500: "HTTP-ALT", 9530: "HTTP-ALT",
    9600: "HTTP-ALT", 9696: "Tomcat", 9876: "HTTP-ALT",
    9900: "FTP-SSL", 9990: "WildFly", 9999: "HTTP-ALT",
    10000: "Webmin", 10001: "HTTP-ALT", 10002: "HTTP-ALT",
    10003: "HTTP-ALT", 10010: "HTTP-ALT", 10050: "Zabbix-Agent",
    10051: "Zabbix-Server", 10134: "Oracle-OEM", 10137: "Oracle-OEM",
    10250: "Kubernetes-Kubelet", 10255: "Kubernetes-Kubelet-RO",
    10389: "Apache-DS", 10443: "HTTPS-ALT", 10505: "HTTP-ALT",
    10555: "HTTP-ALT", 10666: "HTTP-ALT", 10800: "HTTP-ALT",
    10880: "HTTP-ALT", 10999: "HTTP-ALT", 11000: "HTTP-ALT",
    11001: "HTTP-ALT", 11211: "Memcached", 11214: "Memcached",
    11215: "Memcached", 12000: "HTTP-ALT", 12345: "NetBus",
    12346: "NetBus", 12378: "HTTP-ALT", 12443: "HTTP-ALT",
    13306: "MySQL-ALT", 13307: "MySQL-ALT", 13579: "HTTP-ALT",
    14000: "HTTP-ALT", 14147: "FTP-ALT", 14250: "HTTP-ALT",
    14444: "HTTP-ALT", 14500: "HTTP-ALT", 14941: "HTTP-ALT",
    15000: "HTTP-ALT", 15001: "HTTP-ALT", 15002: "HTTP-ALT",
    15151: "HTTP-ALT", 15222: "HTTP-ALT", 15333: "HTTP-ALT",
    15672: "RabbitMQ", 16010: "HBase", 16020: "HBase",
    16030: "HBase", 16111: "HTTP-ALT", 16200: "HTTP-ALT",
    16379: "Redis-ALT", 16500: "HTTP-ALT", 16600: "HTTP-ALT",
    16888: "HTTP-ALT", 17000: "HTTP-ALT", 17001: "HTTP-ALT",
    17230: "Jenkins-ALT", 17300: "Gitea-ALT", 17888: "HTTP-ALT",
    18000: "HTTP-ALT", 18001: "HTTP-ALT", 18080: "HTTP-ALT",
    18081: "HTTP-ALT", 18082: "HTTP-ALT", 18090: "HTTP-ALT",
    18101: "HTTP-ALT", 18102: "HTTP-ALT", 18443: "HTTPS-ALT",
    18686: "HTTP-ALT", 18801: "HTTP-ALT", 18888: "HTTP-ALT",
    18989: "HTTP-ALT", 19000: "HTTP-ALT", 19001: "HTTP-ALT",
    19100: "HTTP-ALT", 19101: "HTTP-ALT", 19200: "HTTP-ALT",
    19283: "HTTP-ALT", 19300: "HTTP-ALT", 19443: "HTTPS-ALT",
    19505: "HTTP-ALT", 19595: "HTTP-ALT", 19680: "HTTP-ALT",
    19800: "HTTP-ALT", 19999: "HTTP-ALT", 20000: "HTTP-ALT",
    20001: "HTTP-ALT", 20010: "HTTP-ALT", 20080: "HTTP-ALT",
    20100: "HTTP-ALT", 20101: "HTTP-ALT", 20200: "HTTP-ALT",
    20210: "HTTP-ALT", 20300: "HTTP-ALT", 20443: "HTTPS-ALT",
    20500: "HTTP-ALT", 20550: "HTTP-ALT", 20666: "HTTP-ALT",
    20720: "HTTP-ALT", 20808: "HTTP-ALT", 20880: "Dubbo",
    21000: "HTTP-ALT", 21001: "HTTP-ALT", 21025: "HTTP-ALT",
    21212: "HTTP-ALT", 21379: "HTTP-ALT", 21505: "HTTP-ALT",
    21810: "HTTP-ALT", 21811: "HTTP-ALT", 21812: "HTTP-ALT",
    21813: "HTTP-ALT", 21818: "HTTP-ALT", 21881: "HTTP-ALT",
    22000: "HTTP-ALT", 22122: "HTTP-ALT", 22222: "SSH-ALT",
    22223: "SSH-ALT", 22333: "HTTP-ALT", 22443: "HTTPS-ALT",
    22555: "HTTP-ALT", 22777: "HTTP-ALT", 22888: "HTTP-ALT",
    23000: "HTTP-ALT", 23232: "HTTP-ALT", 23333: "HTTP-ALT",
    23456: "HTTP-ALT", 23688: "HTTP-ALT", 24000: "HTTP-ALT",
    24224: "Fluentd", 24242: "HTTP-ALT", 24333: "HTTP-ALT",
    24444: "HTTP-ALT", 24466: "HTTP-ALT", 24800: "Synergy",
    25000: "HTTP-ALT", 25001: "HTTP-ALT", 25565: "Minecraft",
    25672: "RabbitMQ", 25888: "HTTP-ALT", 26000: "HTTP-ALT",
    26222: "HTTP-ALT", 26257: "CockroachDB", 26333: "HTTP-ALT",
    26666: "HTTP-ALT", 27017: "MongoDB", 27018: "MongoDB",
    27019: "MongoDB", 27020: "MongoDB", 27021: "MongoDB",
    27777: "HTTP-ALT", 28015: "RethinkDB", 28017: "MongoDB-Web",
    28111: "HTTP-ALT", 28282: "HTTP-ALT", 28443: "HTTPS-ALT",
    28888: "HTTP-ALT", 29000: "HTTP-ALT", 29001: "HTTP-ALT",
    29100: "HTTP-ALT", 29200: "HTTP-ALT", 30000: "HTTP-ALT",
    30001: "HTTP-ALT", 30080: "HTTP-ALT", 30120: "HTTP-ALT",
    30200: "HTTP-ALT", 30303: "Ethereum", 30443: "HTTPS-ALT",
    30555: "HTTP-ALT", 30666: "HTTP-ALT", 30777: "HTTP-ALT",
    30888: "HTTP-ALT", 31000: "HTTP-ALT", 31111: "HTTP-ALT",
    31280: "HTTP-ALT", 31333: "HTTP-ALT", 31443: "HTTPS-ALT",
    31555: "HTTP-ALT", 31666: "HTTP-ALT", 31777: "HTTP-ALT",
    31888: "HTTP-ALT", 31999: "HTTP-ALT", 32000: "HTTP-ALT",
    32111: "HTTP-ALT", 32222: "HTTP-ALT", 32333: "HTTP-ALT",
    32443: "HTTPS-ALT", 32444: "HTTPS-ALT", 32555: "HTTP-ALT",
    32666: "HTTP-ALT", 32777: "HTTP-ALT", 32778: "HTTP-ALT",
    32779: "HTTP-ALT", 32780: "HTTP-ALT", 32781: "HTTP-ALT",
    32782: "HTTP-ALT", 32888: "HTTP-ALT", 32999: "HTTP-ALT",
    33000: "HTTP-ALT", 33033: "HTTP-ALT", 33060: "MySQL-X",
    33133: "HTTP-ALT", 33222: "HTTP-ALT", 33333: "HTTP-ALT",
    33443: "HTTPS-ALT", 33555: "HTTP-ALT", 33666: "HTTP-ALT",
    33777: "HTTP-ALT", 33888: "HTTP-ALT", 33999: "HTTP-ALT",
    34000: "HTTP-ALT", 34111: "HTTP-ALT", 34222: "HTTP-ALT",
    34333: "HTTP-ALT", 34443: "HTTPS-ALT", 34444: "HTTPS-ALT",
    34555: "HTTP-ALT", 34666: "HTTP-ALT", 34777: "HTTP-ALT",
    34888: "HTTP-ALT", 35000: "HTTP-ALT", 35111: "HTTP-ALT",
    35222: "HTTP-ALT", 35333: "HTTP-ALT", 35443: "HTTPS-ALT",
    35555: "HTTP-ALT", 35666: "HTTP-ALT", 35777: "HTTP-ALT",
    35888: "HTTP-ALT", 36000: "HTTP-ALT", 36111: "HTTP-ALT",
    36222: "HTTP-ALT", 36333: "HTTP-ALT", 36443: "HTTPS-ALT",
    36555: "HTTP-ALT", 36666: "HTTP-ALT", 36777: "HTTP-ALT",
    36888: "HTTP-ALT", 36999: "HTTP-ALT", 37000: "HTTP-ALT",
    37111: "HTTP-ALT", 37222: "HTTP-ALT", 37333: "HTTP-ALT",
    37443: "HTTPS-ALT", 37555: "HTTP-ALT", 37666: "HTTP-ALT",
    37777: "HTTP-ALT", 37888: "HTTP-ALT", 37999: "HTTP-ALT",
    38000: "HTTP-ALT", 38111: "HTTP-ALT", 38222: "HTTP-ALT",
    38333: "HTTP-ALT", 38443: "HTTPS-ALT", 38555: "HTTP-ALT",
    38666: "HTTP-ALT", 38777: "HTTP-ALT", 38888: "HTTP-ALT",
    38999: "HTTP-ALT", 39000: "HTTP-ALT", 39111: "HTTP-ALT",
    39222: "HTTP-ALT", 39333: "HTTP-ALT", 39443: "HTTPS-ALT",
    39555: "HTTP-ALT", 39666: "HTTP-ALT", 39777: "HTTP-ALT",
    39888: "HTTP-ALT", 39999: "HTTP-ALT", 40000: "HTTP-ALT",
    41080: "HTTP-ALT", 41111: "HTTP-ALT", 41234: "HTTP-ALT",
    42000: "HTTP-ALT", 42001: "HTTP-ALT", 42002: "HTTP-ALT",
    43000: "HTTP-ALT", 43111: "HTTP-ALT", 43211: "HTTP-ALT",
    43333: "HTTP-ALT", 44000: "HTTP-ALT", 44111: "HTTP-ALT",
    44222: "HTTP-ALT", 44333: "HTTP-ALT", 44405: "HTTP-ALT",
    44444: "HTTP-ALT", 44555: "HTTP-ALT", 44666: "HTTP-ALT",
    44777: "HTTP-ALT", 44888: "HTTP-ALT", 45000: "HTTP-ALT",
    45111: "HTTP-ALT", 45222: "HTTP-ALT", 45333: "HTTP-ALT",
    45443: "HTTPS-ALT", 45555: "HTTP-ALT", 45678: "HTTP-ALT",
    45888: "HTTP-ALT", 46000: "HTTP-ALT", 46111: "HTTP-ALT",
    46222: "HTTP-ALT", 46333: "HTTP-ALT", 46443: "HTTPS-ALT",
    46555: "HTTP-ALT", 46666: "HTTP-ALT", 46888: "HTTP-ALT",
    47000: "HTTP-ALT", 47111: "HTTP-ALT", 47222: "HTTP-ALT",
    47333: "HTTP-ALT", 47443: "HTTPS-ALT", 47555: "HTTP-ALT",
    47777: "HTTP-ALT", 47888: "HTTP-ALT", 48000: "HTTP-ALT",
    48111: "HTTP-ALT", 48222: "HTTP-ALT", 48333: "HTTP-ALT",
    48443: "HTTPS-ALT", 48555: "HTTP-ALT", 48666: "HTTP-ALT",
    48777: "HTTP-ALT", 48888: "HTTP-ALT", 49000: "HTTP-ALT",
    49111: "HTTP-ALT", 49152: "Windows-RPC", 49153: "Windows-RPC",
    49154: "Windows-RPC", 49155: "Windows-RPC", 49156: "Windows-RPC",
    50000: "HTTP-ALT", 50001: "HTTP-ALT", 50010: "HDFS",
    50020: "HDFS", 50030: "Hadoop", 50060: "Hadoop", 50070: "HDFS-Web",
    50075: "HDFS-Web", 50090: "HDFS", 50100: "HTTP-ALT",
    50200: "HTTP-ALT", 50300: "HTTP-ALT", 50400: "HTTP-ALT",
    50500: "HTTP-ALT", 50600: "HTTP-ALT", 50700: "HTTP-ALT",
    50800: "HTTP-ALT", 50900: "HTTP-ALT", 51000: "HTTP-ALT",
    51111: "HTTP-ALT", 52000: "HTTP-ALT", 52111: "HTTP-ALT",
    53000: "HTTP-ALT", 54000: "HTTP-ALT", 55000: "HTTP-ALT",
    55553: "HTTP-ALT", 55555: "HTTP-ALT", 55672: "RabbitMQ",
    56000: "HTTP-ALT", 56111: "HTTP-ALT", 56789: "HTTP-ALT",
    57000: "HTTP-ALT", 57111: "HTTP-ALT", 57222: "HTTP-ALT",
    57333: "HTTP-ALT", 57443: "HTTPS-ALT", 57575: "HTTP-ALT",
    58080: "HTTP-ALT", 59000: "HTTP-ALT", 59111: "HTTP-ALT",
    59222: "HTTP-ALT", 60000: "HTTP-ALT", 60111: "HTTP-ALT",
    61000: "HTTP-ALT", 61111: "HTTP-ALT", 61222: "HTTP-ALT",
    61333: "HTTP-ALT", 61443: "HTTPS-ALT", 61616: "ActiveMQ",
    62000: "HTTP-ALT", 62001: "HTTP-ALT", 63000: "HTTP-ALT",
    64000: "HTTP-ALT", 65000: "HTTP-ALT", 65111: "HTTP-ALT",
    65535: "HTTP-ALT",
}

# Top 100 快速扫描端口
TOP_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143,
             161, 389, 443, 445, 465, 500, 502, 512, 513, 514, 523,
             548, 554, 587, 623, 636, 873, 902, 993, 995, 1080, 1099,
             1194, 1241, 1352, 1433, 1521, 2049, 2082, 2083, 2086, 2087,
             2222, 2375, 2376, 2424, 3000, 3128, 3306, 3312, 3389, 3690,
             4000, 4040, 4444, 4560, 4711, 4848, 5000, 5001, 5432, 5555,
             5601, 5672, 5900, 6000, 6379, 6443, 7001, 7002, 7070,
             7077, 7199, 7474, 7547, 8000, 8001, 8008, 8009, 8010,
             8060, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
             8088, 8089, 8090, 8091, 8092, 8096, 8161, 8200, 8222,
             8443, 8530, 8531, 8649, 8686, 8787, 8834, 8880, 8888,
             8983, 9000, 9001, 9042, 9050, 9060, 9080, 9090, 9092,
             9100, 9119, 9160, 9191, 9200, 9300, 9418, 9443, 9696,
             9876, 9900, 9990, 9999, 10000, 10050, 10051, 10250, 10255,
             11211, 12345, 13306, 15672, 16010, 16379, 17001, 18080,
             18081, 18082, 19000, 19001, 20000, 20880, 21000, 22122,
             22222, 23333, 24224, 24800, 25565, 25672, 26257, 27017,
             28017, 30000, 30120, 30303, 30777, 31111, 31333, 32222,
             32777, 32778, 33060, 33333, 33443, 34443, 35000, 35555,
             36666, 37777, 38888, 39999, 40000, 41080, 41111, 42000,
             43000, 44000, 44444, 45000, 45555, 46000, 47000, 48000,
             49152, 49153, 49154, 49155, 49156, 50000, 50070, 50075,
             50100, 50200, 50300, 50400, 50500, 50600, 50700, 50800,
             50900, 51000, 51111, 52000, 53000, 54000, 55000, 55555,
             55672, 56000, 56789, 57000, 58080, 59000, 60000, 61000,
             61616, 62000, 63000, 64000, 65000, 65535]


async def _scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    """扫描单个端口"""
    async with sem:
        try:
            t1 = asyncio.get_event_loop().time()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            t2 = asyncio.get_event_loop().time()
            writer.close()
            await writer.wait_closed()
            service = COMMON_PORTS.get(port, "Unknown")
            return {
                "port": port,
                "state": "open",
                "service": service,
                "time_ms": int((t2 - t1) * 1000),
            }
        except (OSError, asyncio.TimeoutError):
            return {"port": port, "state": "closed", "service": "", "time_ms": 0}


async def bb_port_scan(
    target: str,
    ports: str = "top100",
    timeout: int = 3,
    concurrent: int = 200,
) -> str:
    """
    端口扫描 — TCP Connect 方式，无第三方依赖

    Args:
        target: 目标 IP 或域名
        ports: 端口范围，如 "80,443,8080-8090"，默认 "top100"
        timeout: 单端口超时秒数（默认 3）
        concurrent: 并发数（默认 200）

    Returns:
        开放端口列表及服务识别
    """
    if ports.lower() == "top100":
        port_list = TOP_PORTS
    else:
        port_list = parse_ports(ports)

    host = target.strip()

    # 先解析域名
    try:
        import socket as sock
        ip = sock.gethostbyname(host)
    except Exception:
        ip = host

    sem = asyncio.Semaphore(concurrent)
    tasks = [_scan_port(host, p, timeout, sem) for p in port_list]

    results = []
    total = len(port_list)
    results.append(f"[*] 目标: {host} ({ip})")
    results.append(f"[*] 扫描端口数: {total}")
    results.append("")

    done = await asyncio.gather(*tasks)
    open_ports = [r for r in done if r["state"] == "open"]

    if not open_ports:
        results.append("[!] 未发现开放端口")
    else:
        results.append(f"[✓] 发现 {len(open_ports)} 个开放端口:")
        results.append(f"    {'端口':<8} {'服务':<20} {'延迟':<8}")
        results.append(f"    {'-'*40}")
        for r in sorted(open_ports, key=lambda x: x["port"]):
            results.append(f"    {r['port']:<8} {r['service']:<20} {r['time_ms']}ms")

    return "\n".join(results)
