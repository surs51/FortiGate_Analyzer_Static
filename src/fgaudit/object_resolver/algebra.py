from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1
PORT_MAX = 65535
PROTO_MAX = 255

V4 = "4"
V6 = "6"
ANY_FAMILY = "*"


@dataclass(frozen=True)
class IntervalSet:
    intervals: tuple[tuple[int, int], ...] = ()

    @staticmethod
    def _merge(raw: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
        ordered = sorted((lo, hi) for lo, hi in raw if lo <= hi)
        out: list[tuple[int, int]] = []
        for lo, hi in ordered:
            if out and lo <= out[-1][1] + 1:
                if hi > out[-1][1]:
                    out[-1] = (out[-1][0], hi)
            else:
                out.append((lo, hi))
        return tuple(out)

    @classmethod
    def of(cls, ivs: Iterable[tuple[int, int]]) -> "IntervalSet":
        return cls(cls._merge(ivs))

    @classmethod
    def empty(cls) -> "IntervalSet":
        return cls(())

    @classmethod
    def closed(cls, lo: int, hi: int) -> "IntervalSet":
        return cls.of([(lo, hi)])

    def is_empty(self) -> bool:
        return not self.intervals

    def covers(self, point: int) -> bool:
        return any(lo <= point <= hi for lo, hi in self.intervals)

    def count(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.intervals)

    def union(self, other: "IntervalSet") -> "IntervalSet":
        return IntervalSet.of(self.intervals + other.intervals)

    def intersection(self, other: "IntervalSet") -> "IntervalSet":
        out: list[tuple[int, int]] = []
        i = j = 0
        a, b = self.intervals, other.intervals
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return IntervalSet(tuple(out))

    def difference(self, other: "IntervalSet") -> "IntervalSet":
        out: list[tuple[int, int]] = []
        for lo, hi in self.intervals:
            cur = lo
            for olo, ohi in other.intervals:
                if ohi < cur:
                    continue
                if olo > hi:
                    break
                if olo > cur:
                    out.append((cur, olo - 1))
                cur = max(cur, ohi + 1)
                if cur > hi:
                    break
            if cur <= hi:
                out.append((cur, hi))
        return IntervalSet.of(out)

    def complement(self, lo: int, hi: int) -> "IntervalSet":
        return IntervalSet.closed(lo, hi).difference(self)

    def is_subset_of(self, other: "IntervalSet") -> bool:
        return self.difference(other).is_empty()

    def intersects(self, other: "IntervalSet") -> bool:
        return not self.intersection(other).is_empty()

    def __or__(self, other: "IntervalSet") -> "IntervalSet":
        return self.union(other)

    def __and__(self, other: "IntervalSet") -> "IntervalSet":
        return self.intersection(other)

    def __sub__(self, other: "IntervalSet") -> "IntervalSet":
        return self.difference(other)

    def __bool__(self) -> bool:
        return not self.is_empty()


_FULL_V4 = IntervalSet.closed(0, V4_MAX)
_FULL_V6 = IntervalSet.closed(0, V6_MAX)


def _tag_family(tag: str) -> str:
    return tag.split("|", 1)[0] if "|" in tag else ANY_FAMILY


def tag_label(tag: str) -> str:
    return tag.split("|", 1)[1] if "|" in tag else tag


def _net_to_ipset(net: ipaddress._BaseNetwork) -> "IPSet":
    lo = int(net.network_address)
    hi = int(net.broadcast_address)
    if net.version == 4:
        return IPSet(IntervalSet.closed(lo, hi), IntervalSet.empty())
    return IPSet(IntervalSet.empty(), IntervalSet.closed(lo, hi))


def ipset_from_subnet_tokens(tokens: list[str]) -> "IPSet":
    try:
        if len(tokens) >= 2:
            net = ipaddress.ip_network(f"{tokens[0]}/{tokens[1]}", strict=False)
        else:
            tok = tokens[0]
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
            else:
                addr = ipaddress.ip_address(tok)
                net = ipaddress.ip_network(f"{tok}/{32 if addr.version == 4 else 128}")
        return _net_to_ipset(net)
    except (ValueError, IndexError):
        return IPSet.opaque_of(f"bad-subnet:{' '.join(tokens)}")


def ipset_from_range(start: str, end: str) -> "IPSet":
    try:
        a = ipaddress.ip_address(start)
        b = ipaddress.ip_address(end)
        lo, hi = sorted((int(a), int(b)))
        if a.version == 4:
            return IPSet(IntervalSet.closed(lo, hi), IntervalSet.empty())
        return IPSet(IntervalSet.empty(), IntervalSet.closed(lo, hi))
    except ValueError:
        return IPSet.opaque_of(f"bad-range:{start}-{end}")


def ipset_from_spec(spec: str) -> "IPSet":
    spec = spec.strip()
    if "-" in spec and "/" not in spec:
        a, _, b = spec.partition("-")
        return ipset_from_range(a.strip(), b.strip())
    return ipset_from_subnet_tokens([spec])


@dataclass(frozen=True)
class IPSet:
    v4: IntervalSet = IntervalSet()
    v6: IntervalSet = IntervalSet()
    opaque: frozenset[str] = frozenset()
    inexact: bool = False

    @classmethod
    def empty(cls) -> "IPSet":
        return cls()

    @classmethod
    def universe(cls) -> "IPSet":
        return cls(_FULL_V4, _FULL_V6)

    @classmethod
    def v4_universe(cls) -> "IPSet":
        return cls(_FULL_V4, IntervalSet.empty())

    @classmethod
    def v6_universe(cls) -> "IPSet":
        return cls(IntervalSet.empty(), _FULL_V6)

    @classmethod
    def opaque_of(cls, tag: str, family: str = ANY_FAMILY) -> "IPSet":
        return cls(opaque=frozenset({f"{family}|{tag}"}))

    def union(self, other: "IPSet") -> "IPSet":
        return IPSet(self.v4 | other.v4, self.v6 | other.v6,
                     self.opaque | other.opaque, self.inexact or other.inexact)

    def intersection(self, other: "IPSet") -> "IPSet":
        return IPSet(self.v4 & other.v4, self.v6 & other.v6,
                     self.opaque & other.opaque, self.inexact or other.inexact)

    def minus(self, other: "IPSet") -> "IPSet":
        unresolved = bool(other.opaque - self.opaque) or other.inexact
        return IPSet(self.v4 - other.v4, self.v6 - other.v6,
                     self.opaque - other.opaque, self.inexact or unresolved)

    def complement(self, families: Iterable[str]) -> "IPSet":
        fams = set(families)
        v4 = self.v4.complement(0, V4_MAX) if V4 in fams else IntervalSet.empty()
        v6 = self.v6.complement(0, V6_MAX) if V6 in fams else IntervalSet.empty()
        return IPSet(v4, v6, frozenset(), self.inexact or bool(self.opaque))

    def covers(self, other: "IPSet") -> bool:
        if self.inexact or other.inexact:
            return False
        if not other.v4.is_subset_of(self.v4) or not other.v6.is_subset_of(self.v6):
            return False
        for tag in other.opaque - self.opaque:
            family = _tag_family(tag)
            if family == V4 and self.is_v4_universe():
                continue
            if family == V6 and self.is_v6_universe():
                continue
            if self.is_universe():
                continue
            return False
        return True

    def is_subset_of(self, other: "IPSet") -> bool:
        return other.covers(self)

    def overlaps(self, other: "IPSet") -> bool:
        if self.v4.intersects(other.v4) or self.v6.intersects(other.v6):
            return True
        if self.opaque & other.opaque:
            return True
        for a, b in ((self, other), (other, self)):
            for tag in b.opaque:
                family = _tag_family(tag)
                if family in (V4, ANY_FAMILY) and a.is_v4_universe():
                    return True
                if family in (V6, ANY_FAMILY) and a.is_v6_universe():
                    return True
        return False

    def is_empty(self) -> bool:
        return self.v4.is_empty() and self.v6.is_empty() and not self.opaque

    def is_v4_universe(self) -> bool:
        return self.v4 == _FULL_V4

    def is_v6_universe(self) -> bool:
        return self.v6 == _FULL_V6

    def is_universe(self) -> bool:
        return self.is_v4_universe() and self.is_v6_universe()

    def is_broad(self) -> bool:
        return (self.is_v4_universe() or self.is_v6_universe()
                or self.v4.count() >= (1 << 31))

    def has_opaque(self) -> bool:
        return bool(self.opaque)

    def is_determinate(self) -> bool:
        return not self.opaque and not self.inexact

    def v4_count(self) -> int:
        return self.v4.count()

    def __or__(self, other: "IPSet") -> "IPSet":
        return self.union(other)


def ipset_to_strings(s: IPSet, limit: int = 8) -> list[str]:
    if s.is_empty():
        return ["nothing"]
    out: list[str] = []
    if s.is_universe():
        out.append("any address")
    else:
        if s.is_v4_universe():
            out.append("any IPv4 address")
        else:
            for lo, hi in s.v4.intervals:
                out.extend(_int_range_to_cidrs(lo, hi, 4))
        if s.is_v6_universe():
            out.append("any IPv6 address")
        else:
            for lo, hi in s.v6.intervals:
                out.extend(_int_range_to_cidrs(lo, hi, 6))
    out.extend(sorted(tag_label(t) for t in s.opaque))
    if s.inexact:
        out.append("(approximate)")
    if len(out) > limit:
        return out[:limit] + [f"and {len(out) - limit} more"]
    return out or ["nothing"]


def _int_range_to_cidrs(lo: int, hi: int, version: int) -> list[str]:
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    try:
        nets = list(ipaddress.summarize_address_range(cls(lo), cls(hi)))
    except (ValueError, ipaddress.AddressValueError):
        return [f"{cls(lo)}-{cls(hi)}"]
    if len(nets) > 4:
        return [f"{cls(lo)}-{cls(hi)}"]
    return [str(n) for n in nets]


_FULL_PORTS = IntervalSet.closed(0, PORT_MAX)
_FULL_PROTO = IntervalSet.closed(0, PROTO_MAX)


@dataclass(frozen=True)
class ServiceSet:
    tcp: IntervalSet = IntervalSet()
    udp: IntervalSet = IntervalSet()
    sctp: IntervalSet = IntervalSet()
    icmp: IntervalSet = IntervalSet()
    ip_proto: IntervalSet = IntervalSet()
    opaque: frozenset[str] = frozenset()
    inexact: bool = False

    @classmethod
    def empty(cls) -> "ServiceSet":
        return cls()

    @classmethod
    def all(cls) -> "ServiceSet":
        return cls(_FULL_PORTS, _FULL_PORTS, _FULL_PORTS, _FULL_PROTO, _FULL_PROTO)

    @classmethod
    def opaque_of(cls, tag: str) -> "ServiceSet":
        return cls(opaque=frozenset({tag}))

    def _dims(self) -> tuple[IntervalSet, ...]:
        return (self.tcp, self.udp, self.sctp, self.icmp, self.ip_proto)

    def union(self, other: "ServiceSet") -> "ServiceSet":
        return ServiceSet(
            self.tcp | other.tcp, self.udp | other.udp, self.sctp | other.sctp,
            self.icmp | other.icmp, self.ip_proto | other.ip_proto,
            self.opaque | other.opaque, self.inexact or other.inexact,
        )

    def intersection(self, other: "ServiceSet") -> "ServiceSet":
        if self.is_all() and not self.inexact:
            return other
        if other.is_all() and not other.inexact:
            return self
        return ServiceSet(
            self.tcp & other.tcp, self.udp & other.udp, self.sctp & other.sctp,
            self.icmp & other.icmp, self.ip_proto & other.ip_proto,
            self.opaque & other.opaque, self.inexact or other.inexact,
        )

    def complement(self) -> "ServiceSet":
        return ServiceSet(
            self.tcp.complement(0, PORT_MAX), self.udp.complement(0, PORT_MAX),
            self.sctp.complement(0, PORT_MAX), self.icmp.complement(0, PROTO_MAX),
            self.ip_proto.complement(0, PROTO_MAX), frozenset(),
            self.inexact or bool(self.opaque),
        )

    def is_subset_of(self, other: "ServiceSet") -> bool:
        return other.covers(self)

    def covers(self, other: "ServiceSet") -> bool:
        if self.inexact or other.inexact:
            return False
        if self.is_all():
            return True
        return (all(a.is_subset_of(b) for a, b in zip(other._dims(), self._dims()))
                and other.opaque <= self.opaque)

    def overlaps(self, other: "ServiceSet") -> bool:
        if self.is_empty() or other.is_empty():
            return False
        if self.is_all() or other.is_all():
            return True
        return (any(a.intersects(b) for a, b in zip(self._dims(), other._dims()))
                or bool(self.opaque & other.opaque))

    def is_empty(self) -> bool:
        return all(d.is_empty() for d in self._dims()) and not self.opaque

    def is_all(self) -> bool:
        return (self.tcp == _FULL_PORTS and self.udp == _FULL_PORTS
                and self.sctp == _FULL_PORTS and self.icmp == _FULL_PROTO
                and self.ip_proto == _FULL_PROTO)

    def whole_protocols(self) -> list[str]:
        out = []
        for label, dim in (("TCP", self.tcp), ("UDP", self.udp)):
            if IntervalSet.closed(1, PORT_MAX).is_subset_of(dim):
                out.append(label)
        return out

    def is_determinate(self) -> bool:
        return not self.opaque and not self.inexact

    def carries(self, proto: str, port: int) -> bool:
        if self.is_all():
            return True
        dim = {"tcp": self.tcp, "udp": self.udp, "sctp": self.sctp,
               "icmp": self.icmp}.get(proto.lower())
        return bool(dim and dim.covers(port))

    def __or__(self, other: "ServiceSet") -> "ServiceSet":
        return self.union(other)


def _ranges(s: IntervalSet) -> list[str]:
    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in s.intervals]


def service_to_strings(s: ServiceSet) -> list[str]:
    if s.is_all():
        return ["ALL"]
    parts: list[str] = []
    for label, dim in (("tcp", s.tcp), ("udp", s.udp), ("sctp", s.sctp),
                       ("icmp-type", s.icmp), ("ip-proto", s.ip_proto)):
        if dim:
            parts.append(f"{label}/" + ",".join(_ranges(dim)))
    parts.extend(sorted(s.opaque))
    if s.inexact:
        parts.append("(approximate)")
    return parts or ["nothing"]


def _svc(tcp=None, udp=None, sctp=None, icmp=None, ipp=None) -> ServiceSet:
    def mk(spec) -> IntervalSet:
        if not spec:
            return IntervalSet.empty()
        return IntervalSet.of(item if isinstance(item, tuple) else (item, item)
                              for item in spec)

    return ServiceSet(mk(tcp), mk(udp), mk(sctp), mk(icmp), mk(ipp))


BUILTIN_SERVICES: dict[str, ServiceSet] = {
    "ALL": ServiceSet.all(),
    "ALL_TCP": _svc(tcp=[(1, PORT_MAX)]),
    "ALL_UDP": _svc(udp=[(1, PORT_MAX)]),
    "ALL_SCTP": _svc(sctp=[(1, PORT_MAX)]),
    "ALL_ICMP": _svc(icmp=[(0, PROTO_MAX)]),
    "ALL_ICMP6": _svc(ipp=[58]),
    "AFS3": _svc(tcp=[(7000, 7009)], udp=[(7000, 7009)]),
    "AH": _svc(ipp=[51]),
    "AOL": _svc(tcp=[(5190, 5194)]),
    "BGP": _svc(tcp=[179]),
    "CVSPSERVER": _svc(tcp=[2401], udp=[2401]),
    "DCE-RPC": _svc(tcp=[135], udp=[135]),
    "DHCP": _svc(udp=[(67, 68)]),
    "DHCP6": _svc(udp=[(546, 547)]),
    "DNS": _svc(tcp=[53], udp=[53]),
    "ESP": _svc(ipp=[50]),
    "FINGER": _svc(tcp=[79]),
    "FTP": _svc(tcp=[21]),
    "FTP_GET": _svc(tcp=[21]),
    "FTP_PUT": _svc(tcp=[21]),
    "GOPHER": _svc(tcp=[70]),
    "GRE": _svc(ipp=[47]),
    "H323": _svc(tcp=[1720, 1503], udp=[1719]),
    "HTTP": _svc(tcp=[80]),
    "HTTPS": _svc(tcp=[443]),
    "IKE": _svc(udp=[500, 4500]),
    "IMAP": _svc(tcp=[143]),
    "IMAPS": _svc(tcp=[993]),
    "INFO_ADDRESS": _svc(icmp=[17]),
    "INFO_REQUEST": _svc(icmp=[15]),
    "INTERNET-LOCATOR-SERVICE": _svc(tcp=[389]),
    "IRC": _svc(tcp=[(6660, 6669)]),
    "KERBEROS": _svc(tcp=[88], udp=[88]),
    "L2TP": _svc(tcp=[1701], udp=[1701]),
    "LDAP": _svc(tcp=[389]),
    "LDAP_UDP": _svc(udp=[389]),
    "LDAPS": _svc(tcp=[636]),
    "MGCP": _svc(udp=[2427, 2727]),
    "MMS": _svc(tcp=[1755], udp=[(1024, 5000)]),
    "MS-SQL": _svc(tcp=[1433, 1434]),
    "MYSQL": _svc(tcp=[3306]),
    "NETMEETING": _svc(tcp=[1720]),
    "NFS": _svc(tcp=[111, 2049], udp=[111, 2049]),
    "NNTP": _svc(tcp=[119]),
    "NTP": _svc(tcp=[123], udp=[123]),
    "ONC-RPC": _svc(tcp=[111], udp=[111]),
    "OSPF": _svc(ipp=[89]),
    "PC-ANYWHERE": _svc(tcp=[5631], udp=[5632]),
    "PING": _svc(icmp=[8]),
    "PING6": _svc(ipp=[58]),
    "POP3": _svc(tcp=[110]),
    "POP3S": _svc(tcp=[995]),
    "POSTGRESQL": _svc(tcp=[5432]),
    "PPTP": _svc(tcp=[1723]),
    "QUAKE": _svc(udp=[26000, 27000, 27910, 27960]),
    "RADIUS": _svc(udp=[(1812, 1813)]),
    "RADIUS-OLD": _svc(udp=[(1645, 1646)]),
    "RAUDIO": _svc(udp=[7070]),
    "RDP": _svc(tcp=[3389]),
    "REDIS": _svc(tcp=[6379]),
    "REXEC": _svc(tcp=[512]),
    "RIP": _svc(udp=[520]),
    "RLOGIN": _svc(tcp=[513]),
    "RSH": _svc(tcp=[514]),
    "RTSP": _svc(tcp=[554, 7070, 8554], udp=[554]),
    "SAMBA": _svc(tcp=[139]),
    "SCCP": _svc(tcp=[2000]),
    "SIP": _svc(tcp=[5060], udp=[5060]),
    "SIP-MSNMESSENGER": _svc(tcp=[1863]),
    "SMB": _svc(tcp=[445]),
    "SMTP": _svc(tcp=[25]),
    "SMTPS": _svc(tcp=[465]),
    "SNMP": _svc(tcp=[(161, 162)], udp=[(161, 162)]),
    "SOCKS": _svc(tcp=[1080], udp=[1080]),
    "SQUID": _svc(tcp=[3128]),
    "SSH": _svc(tcp=[22]),
    "SYSLOG": _svc(udp=[514]),
    "TALK": _svc(udp=[(517, 518)]),
    "TELNET": _svc(tcp=[23]),
    "TFTP": _svc(udp=[69]),
    "TIMESTAMP": _svc(icmp=[13]),
    "TRACEROUTE": _svc(udp=[(33434, 33535)]),
    "UUCP": _svc(tcp=[540]),
    "VDOLIVE": _svc(tcp=[(7000, 7010)]),
    "VNC": _svc(tcp=[5900]),
    "WAIS": _svc(tcp=[210]),
    "WINFRAME": _svc(tcp=[1494, 2598]),
    "WINS": _svc(tcp=[1512], udp=[1512]),
    "X-WINDOWS": _svc(tcp=[(6000, 6063)]),
}


def parse_port_intervals(tokens: list[str]) -> IntervalSet:
    ivs: list[tuple[int, int]] = []
    for tok in tokens:
        dst = tok.split(":", 1)[0]
        for part in dst.split(","):
            part = part.strip()
            if not part:
                continue
            lo_s, sep, hi_s = part.partition("-")
            try:
                lo = int(lo_s)
                hi = int(hi_s) if sep else lo
            except ValueError:
                continue
            ivs.append((min(lo, hi), max(lo, hi)))
    return IntervalSet.of(ivs)


@dataclass(frozen=True)
class InterfaceSet:
    names: frozenset[str] = frozenset()
    is_any: bool = False

    @classmethod
    def any(cls) -> "InterfaceSet":
        return cls(is_any=True)

    @classmethod
    def of(cls, names: Iterable[str]) -> "InterfaceSet":
        return cls(frozenset(names))

    def is_superset_of(self, other: "InterfaceSet") -> bool:
        if self.is_any:
            return True
        if other.is_any:
            return False
        return other.names <= self.names

    def intersects(self, other: "InterfaceSet") -> bool:
        if self.is_any or other.is_any:
            return True
        return bool(self.names & other.names)

    def contains(self, name: str) -> bool:
        return self.is_any or name in self.names

    def union(self, other: "InterfaceSet") -> "InterfaceSet":
        if self.is_any or other.is_any:
            return InterfaceSet.any()
        return InterfaceSet(self.names | other.names)

    def to_strings(self) -> list[str]:
        if self.is_any:
            return ["any"]
        return sorted(self.names) or ["none"]

