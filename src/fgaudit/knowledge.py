from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FosVersion:
    major: int
    minor: int
    patch: Optional[int]

    @property
    def train(self) -> tuple[int, int]:
        return (self.major, self.minor)

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch or 0)

    def at_least(self, major: int, minor: int, patch: int = 0) -> bool:
        return self.as_tuple() >= (major, minor, patch)

    def __str__(self) -> str:
        if self.patch is None:
            return f"{self.major}.{self.minor}"
        return f"{self.major}.{self.minor}.{self.patch}"


_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?$")


def parse_version(text: Optional[str]) -> Optional[FosVersion]:
    if not text:
        return None
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None
    patch = m.group(3)
    return FosVersion(int(m.group(1)), int(m.group(2)), int(patch) if patch else None)


_END_OF_SUPPORT = {
    (6, 0): _dt.date(2022, 9, 29),
    (6, 2): _dt.date(2023, 9, 28),
    (6, 4): _dt.date(2025, 3, 31),
    (7, 0): _dt.date(2026, 3, 31),
}


def is_end_of_support(version: FosVersion, today: _dt.date) -> bool:
    if version.major < 6:
        return True
    eos = _END_OF_SUPPORT.get(version.train)
    return eos is not None and today > eos


@dataclass(frozen=True)
class KnownVuln:
    cve: str
    advisory: str
    summary: str
    feature: str
    affected: tuple[tuple[tuple[int, int, int], tuple[int, int, int]], ...]
    actively_exploited: bool

    def affects(self, version: FosVersion) -> Optional[bool]:
        for low, high in self.affected:
            if (low[0], low[1]) != version.train:
                continue
            if version.patch is None:
                return None
            return low <= version.as_tuple() <= high
        return False


KNOWN_VULNS: tuple[KnownVuln, ...] = (
    KnownVuln(
        "CVE-2018-13379", "FG-IR-18-384",
        "a path traversal in the SSL-VPN web portal that leaks session files "
        "containing plaintext VPN credentials",
        "sslvpn",
        (((5, 4, 6), (5, 4, 12)), ((5, 6, 3), (5, 6, 7)), ((6, 0, 0), (6, 0, 4))),
        True,
    ),
    KnownVuln(
        "CVE-2022-42475", "FG-IR-22-398",
        "a heap overflow in the SSL-VPN daemon that lets an unauthenticated "
        "attacker run code on the firewall",
        "sslvpn",
        (((6, 0, 0), (6, 0, 15)), ((6, 2, 0), (6, 2, 11)), ((6, 4, 0), (6, 4, 10)),
         ((7, 0, 0), (7, 0, 8)), ((7, 2, 0), (7, 2, 2))),
        True,
    ),
    KnownVuln(
        "CVE-2023-27997", "FG-IR-23-097",
        "a heap overflow in the SSL-VPN daemon reachable before login "
        "(known as XORtigate)",
        "sslvpn",
        (((6, 0, 0), (6, 0, 16)), ((6, 2, 0), (6, 2, 13)), ((6, 4, 0), (6, 4, 12)),
         ((7, 0, 0), (7, 0, 11)), ((7, 2, 0), (7, 2, 4))),
        True,
    ),
    KnownVuln(
        "CVE-2024-21762", "FG-IR-24-015",
        "an out-of-bounds write in the SSL-VPN daemon that lets an unauthenticated "
        "attacker run code on the firewall",
        "sslvpn",
        (((6, 0, 0), (6, 0, 17)), ((6, 2, 0), (6, 2, 15)), ((6, 4, 0), (6, 4, 14)),
         ((7, 0, 0), (7, 0, 13)), ((7, 2, 0), (7, 2, 6)), ((7, 4, 0), (7, 4, 2))),
        True,
    ),
    KnownVuln(
        "CVE-2022-40684", "FG-IR-22-377",
        "an authentication bypass on the HTTP/HTTPS admin interface",
        "admin",
        (((7, 0, 0), (7, 0, 6)), ((7, 2, 0), (7, 2, 1))),
        True,
    ),
    KnownVuln(
        "CVE-2024-55591", "FG-IR-24-535",
        "an authentication bypass in the admin interface's websocket module that "
        "hands out super_admin rights",
        "admin",
        (((7, 0, 0), (7, 0, 16)),),
        True,
    ),
    KnownVuln(
        "CVE-2024-23113", "FG-IR-24-029",
        "a format string bug in the FortiManager connection daemon (fgfm) that "
        "can be exploited without logging in",
        "fgfm",
        (((7, 0, 0), (7, 0, 13)), ((7, 2, 0), (7, 2, 6)), ((7, 4, 0), (7, 4, 2))),
        True,
    ),
)


TLS_TCP_PORTS = frozenset({
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 3269, 5061, 8443, 10443,
})
SSH_PORT = 22

RISKY_TCP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    389: "LDAP", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh", 636: "LDAPS",
    873: "rsync", 1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker API", 2376: "Docker API", 3268: "Global Catalog",
    3269: "Global Catalog", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis",
    9200: "Elasticsearch", 10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}
RISKY_TCP_RANGES: tuple[tuple[int, int, str], ...] = ((6000, 6063, "X11"),)
RISKY_UDP: dict[int, str] = {
    69: "TFTP", 111: "RPC", 137: "NetBIOS", 138: "NetBIOS", 161: "SNMP",
    162: "SNMP", 389: "CLDAP", 623: "IPMI", 1434: "MS-SQL Browser", 1900: "SSDP",
    2049: "NFS", 3389: "RDP", 11211: "Memcached",
}
RISKY_SERVICE_NAMES = frozenset({
    "RDP", "SSH", "TELNET", "SMB", "SAMBA", "FTP", "TFTP", "VNC", "SNMP", "LDAP",
    "NFS", "WINRM", "RLOGIN", "REXEC", "RSH", "PPTP", "MYSQL", "MS-SQL", "MSSQL",
    "POSTGRES", "POSTGRESQL", "ORACLE", "NETBIOS", "DCE-RPC", "X-WINDOWS",
})

PREDEFINED_SERVICES = frozenset({
    "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "GRE", "AH", "ESP", "AOL",
    "BGP", "DHCP", "DHCP6", "DNS", "FINGER", "FTP", "FTP_GET", "FTP_PUT", "GOPHER",
    "H323", "HTTP", "HTTPS", "IKE", "IMAP", "IMAPS", "Internet-Locator-Service",
    "IRC", "L2TP", "LDAP", "LDAP_UDP", "NetMeeting", "NFS", "NNTP", "NTP", "OSPF",
    "PC-Anywhere", "PING", "PING6", "TIMESTAMP", "INFO_REQUEST", "INFO_ADDRESS",
    "ONC-RPC", "DCE-RPC", "POP3", "POP3S", "PPTP", "QUAKE", "RAUDIO", "REXEC",
    "RIP", "RLOGIN", "RSH", "SCCP", "SIP", "SIP-MSNmessenger", "SAMBA", "SMTP",
    "SMTPS", "SNMP", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP", "MGCP", "UUCP",
    "VDOLIVE", "WAIS", "WINFRAME", "X-WINDOWS", "MS-SQL", "MYSQL", "RDP", "VNC",
    "SQUID", "SOCKS", "WINS", "RADIUS", "RADIUS-OLD", "CVSPSERVER", "AFS3",
    "TRACEROUTE", "RTSP", "MMS", "KERBEROS", "SMB", "NONE", "webproxy",
    "Email Access", "Web Access", "Windows AD", "Exchange Server",
})

PREDEFINED_ADDRESSES = frozenset({
    "all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE",
    "SSLVPN_TUNNEL_ADDR1", "SSLVPN_TUNNEL_IPv6_ADDR1", "login.microsoftonline.com",
    "login.microsoft.com", "login.windows.net", "gmail.com", "wildcard.google.com",
    "wildcard.dropbox.com", "EMS_ALL_UNKNOWN_CLIENTS",
    "EMS_ALL_UNMANAGEABLE_CLIENTS", "G Suite", "Microsoft Office 365",
})

BUILTIN_PROFILES = frozenset({
    "default", "all_default", "all_default_pass", "sniffer-profile", "Sniffer-profile",
    "g-default", "wifi-default", "block-all-dns", "monitor-all", "flow-monitor-all",
    "flow", "proxy", "high_security", "extended-log", "block-high-risk",
    "protect_client", "protect_email_server", "protect_http_server",
    "deep-inspection", "certificate-inspection", "no-inspection",
    "custom-deep-inspection", "default-extended",
})

SSL_BUILTIN_DEPTH = {
    "deep-inspection": "deep",
    "custom-deep-inspection": "deep",
    "certificate-inspection": "cert",
    "no-inspection": "none",
}

DEFAULT_SSL_CA_NAMES = frozenset({"fortinet_ca_ssl", "fortinet_ca"})

THREAT_CATEGORIES = {26: "Malicious Websites", 61: "Phishing", 86: "Spam URLs"}

WEAK_SSH_KEX = frozenset({
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
})
WEAK_SSH_ENC_MARKERS = ("3des", "arcfour", "blowfish", "cast128", "-cbc")
WEAK_SSH_MAC_MARKERS = ("md5", "sha1", "ripemd160", "umac-64")

WAN_NAME_RE = re.compile(
    r"(?i)(?:^|[^a-z])(?:wan|inet|internet|outside|untrust|isp|ppp|pppoe|wwan|sdwan|uplink)"
)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_public_address(token: str) -> bool:
    try:
        addr = ipaddress.ip_address(token.strip())
    except ValueError:
        return False
    if addr.version == 4 and addr in _CGNAT:
        return True
    return addr.is_global
