from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigModel, ConfigObject
from .algebra import (
    BUILTIN_SERVICES,
    V4,
    V6,
    InterfaceSet,
    IntervalSet,
    IPSet,
    ServiceSet,
    ipset_from_range,
    ipset_from_spec,
    ipset_from_subnet_tokens,
    ipset_to_strings,
    parse_port_intervals,
    service_to_strings,
)

PROFILE_KEYS = (
    "ips-sensor", "av-profile", "webfilter-profile", "dnsfilter-profile",
    "application-list", "dlp-profile", "dlp-sensor", "file-filter-profile",
    "emailfilter-profile", "videofilter-profile", "casb-profile", "icap-profile",
    "waf-profile", "voip-profile", "ssh-filter-profile", "virtual-patch-profile",
)
IDENTITY_KEYS = ("users", "groups", "fsso-groups", "ztna-ems-tag", "ztna-geo-tag")
L7_KEYS = ("application", "app-category", "app-group", "url-category")
ISDB_DST_KEYS = ("internet-service-name", "internet-service-id", "internet-service-group",
                 "internet-service-custom", "internet-service-custom-group",
                 "internet-service-fortiguard")
ISDB_SRC_KEYS = tuple(k.replace("internet-service-", "internet-service-src-")
                      for k in ISDB_DST_KEYS)

_OPAQUE_ADDR_TYPES = {
    "fqdn", "wildcard-fqdn", "geography", "dynamic", "mac", "wildcard", "sdn",
    "route-tag", "template", "ems-tag", "fortivoice-tag", "fortinac-tag",
}
_V4_ADDR_SECTIONS = ("firewall address", "firewall addrgrp", "firewall vip", "firewall vipgrp")
_V6_ADDR_SECTIONS = ("firewall address6", "firewall addrgrp6", "firewall vip6", "firewall vipgrp6")


@dataclass(frozen=True)
class VipInfo:
    name: str
    vdom: str
    kind: str
    external: IPSet
    external_text: str
    mapped: IPSet
    mapped_text: str
    extintf: str
    portforward: bool
    protocol: str
    ext_ports: IntervalSet
    mapped_ports: IntervalSet
    source_filter: tuple[str, ...]
    enabled: bool
    obj: ConfigObject

    def forwarded_service(self) -> Optional[ServiceSet]:
        if not self.portforward:
            return None
        ports = self.mapped_ports or self.ext_ports
        if not ports:
            return None
        if self.protocol == "udp":
            return ServiceSet(udp=ports)
        if self.protocol == "sctp":
            return ServiceSet(sctp=ports)
        if self.protocol == "icmp":
            return ServiceSet(icmp=IntervalSet.closed(0, 255))
        return ServiceSet(tcp=ports)

    def external_label(self) -> str:
        if self.portforward and self.ext_ports:
            ports = ",".join(str(lo) if lo == hi else f"{lo}-{hi}"
                             for lo, hi in self.ext_ports.intervals)
            return f"{self.external_text}:{ports}/{self.protocol}"
        return self.external_text

    def mapped_label(self) -> str:
        ports = self.mapped_ports or (self.ext_ports if self.portforward else IntervalSet())
        if self.portforward and ports:
            shown = ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports.intervals)
            return f"{self.mapped_text}:{shown}"
        return self.mapped_text


@dataclass
class EffectivePolicy:
    policy: ConfigObject
    vdom: str
    src_ip: IPSet
    dst_ip: IPSet
    src_intf: InterfaceSet
    dst_intf: InterfaceSet
    service: ServiceSet
    schedule: str
    action: str
    enabled: bool
    profiles: dict[str, str] = field(default_factory=dict)
    ssl_profile: Optional[str] = None
    utm_enabled: bool = True
    vips: tuple[VipInfo, ...] = ()
    dst_has_plain_address: bool = True
    identity: tuple = ()
    l7: tuple = ()
    match_vip: bool = False
    src_negated: bool = False
    dst_negated: bool = False
    service_negated: bool = False
    uses_isdb: bool = False
    nat: bool = False
    src_display: tuple[str, ...] = ()
    dst_display: tuple[str, ...] = ()

    @property
    def policyid(self) -> str:
        return self.policy.name

    @property
    def name(self) -> str:
        return self.policy.get("name", "") or ""

    @property
    def label(self) -> str:
        n = self.name
        return f"policy {self.policyid}" + (f' "{n}"' if n else "")

    @property
    def short(self) -> str:
        return f"policy {self.policyid}"

    @property
    def is_allow(self) -> bool:
        return self.action in ("accept", "ipsec")

    @property
    def targets_vip(self) -> bool:
        return bool(self.vips)

    def profile_map(self) -> dict[str, str]:
        return dict(self.profiles) if self.utm_enabled else {}

    def has_profiles(self) -> bool:
        return bool(self.profile_map())

    def treatment_key(self) -> tuple:
        return (tuple(sorted(self.profile_map().items())), self.ssl_profile or "")

    def matches_nothing(self) -> bool:
        return self.src_ip.is_empty() or self.dst_ip.is_empty() or self.service.is_empty()

    def inbound_service(self) -> ServiceSet:
        if not self.vips or self.dst_has_plain_address:
            return self.service
        forwarded = [v.forwarded_service() for v in self.vips]
        if any(f is None for f in forwarded):
            return self.service
        acc = ServiceSet.empty()
        for f in forwarded:
            acc = acc.union(self.service.intersection(f))
        return acc

    def schedule_covers(self, other: "EffectivePolicy") -> bool:
        return self.schedule in ("always", "") or self.schedule == other.schedule

    def _vip_semantics_allow(self, other: "EffectivePolicy") -> bool:
        if self.targets_vip == other.targets_vip:
            return True
        plain = other if self.targets_vip else self
        return plain.action == "deny" and plain.match_vip

    def fully_covers(self, other: "EffectivePolicy") -> bool:
        if self.targets_vip != other.targets_vip:
            if self.targets_vip or not (self.action == "deny" and self.match_vip):
                return False
        if self.identity and self.identity != other.identity:
            return False
        if self.l7 and self.l7 != other.l7:
            return False
        return (
            self.src_intf.is_superset_of(other.src_intf)
            and self.dst_intf.is_superset_of(other.dst_intf)
            and self.src_ip.covers(other.src_ip)
            and self.dst_ip.covers(other.dst_ip)
            and self.service.covers(other.service)
            and self.schedule_covers(other)
        )

    def intersects(self, other: "EffectivePolicy") -> bool:
        return (
            self._vip_semantics_allow(other)
            and self.src_intf.intersects(other.src_intf)
            and self.dst_intf.intersects(other.dst_intf)
            and self.src_ip.overlaps(other.src_ip)
            and self.dst_ip.overlaps(other.dst_ip)
            and self.service.overlaps(other.service)
        )

    def evidence(self) -> dict:
        return {
            "srcintf": self.src_intf.to_strings(),
            "dstintf": self.dst_intf.to_strings(),
            "srcaddr": list(self.src_display) or ipset_to_strings(self.src_ip),
            "dstaddr": list(self.dst_display) or ipset_to_strings(self.dst_ip),
            "service": service_to_strings(self.service),
            "action": self.action,
            "schedule": self.schedule,
        }

    def evidence_text(self) -> str:
        e = self.evidence()
        return (f"{', '.join(e['srcintf'])} -> {', '.join(e['dstintf'])}; "
                f"from {', '.join(e['srcaddr'])} to {', '.join(e['dstaddr'])}; "
                f"service {', '.join(e['service'])}; action {e['action']}")


@dataclass
class SetResolver:
    model: ConfigModel
    unresolved: set[str] = field(default_factory=set)
    cycles: list[str] = field(default_factory=list)
    _addr_cache: dict[tuple[str, str, str], IPSet] = field(default_factory=dict)
    _svc_cache: dict[tuple[str, str], ServiceSet] = field(default_factory=dict)
    _by_section: dict[tuple[str, str], dict[str, ConfigObject]] = field(default_factory=dict)
    _eff_cache: dict[str, list[EffectivePolicy]] = field(default_factory=dict)
    _vip_cache: dict[tuple[str, str], Optional[VipInfo]] = field(default_factory=dict)
    _zone_cache: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    def _scopes(self, vdom: str) -> tuple[str, ...]:
        if vdom == GLOBAL_VDOM:
            return (GLOBAL_VDOM,)
        if self.model.multi_vdom:
            return (vdom, GLOBAL_VDOM)
        return (vdom, GLOBAL_VDOM, ROOT_VDOM)

    def _section_map(self, vdom: str, section: str) -> dict[str, ConfigObject]:
        key = (vdom, section)
        if key not in self._by_section:
            self._by_section[key] = {
                o.name: o for o in self.model.local_objects(section, vdom) if o.name
            }
        return self._by_section[key]

    def find(self, vdom: str, section: str, name: str) -> Optional[ConfigObject]:
        for vd in self._scopes(vdom):
            obj = self._section_map(vd, section).get(name)
            if obj is not None:
                return obj
        return None

    def resolve_addr(self, vdom: str, name: str, family: str = V4,
                     _stack: tuple[str, ...] = ()) -> IPSet:
        low = name.lower()
        if low == "all":
            return IPSet.v6_universe() if family == V6 else IPSet.v4_universe()
        if low in ("none", ""):
            return IPSet.empty()
        if name in _stack:
            self.cycles.append(" -> ".join(_stack + (name,)))
            return IPSet.opaque_of(f"group loop at {name}")

        cache_key = (vdom, name, family)
        if not _stack and cache_key in self._addr_cache:
            return self._addr_cache[cache_key]

        sections = (_V6_ADDR_SECTIONS + _V4_ADDR_SECTIONS if family == V6
                    else _V4_ADDR_SECTIONS + _V6_ADDR_SECTIONS)
        result: Optional[IPSet] = None
        for section in sections:
            obj = self.find(vdom, section, name)
            if obj is None:
                continue
            obj_family = V6 if section.endswith("6") else V4
            if section.startswith("firewall address"):
                result = self._resolve_addr_object(vdom, obj, obj_family)
            elif section.startswith("firewall vipgrp") or section.startswith("firewall addrgrp"):
                result = self._resolve_group(vdom, obj, obj_family, _stack + (name,))
            else:
                vip = self.vip_info(vdom, name)
                result = vip.external if vip else IPSet.opaque_of(f"vip:{name}", obj_family)
            break
        if result is None:
            self.unresolved.add(name)
            result = IPSet.opaque_of(f"unknown object {name}")

        if not _stack:
            self._addr_cache[cache_key] = result
        return result

    def _resolve_group(self, vdom: str, grp: ConfigObject, family: str,
                       stack: tuple[str, ...]) -> IPSet:
        acc = IPSet.empty()
        for member in grp.get_list("member"):
            acc = acc.union(self.resolve_addr(vdom, member, family, stack))
        if grp.flag("exclude", False):
            excluded = IPSet.empty()
            for member in grp.get_list("exclude-member"):
                excluded = excluded.union(self.resolve_addr(vdom, member, family, stack))
            acc = acc.minus(excluded)
        return acc

    def _resolve_addr_object(self, vdom: str, obj: ConfigObject, family: str) -> IPSet:
        atype = obj.lower("type")
        if not atype:
            if obj.get("start-ip"):
                atype = "iprange"
            elif obj.get("fqdn"):
                atype = "fqdn"
            elif obj.get("country"):
                atype = "geography"
            elif family == V6:
                atype = "ipprefix"
            else:
                atype = "ipmask"

        if atype in ("ipmask", "subnet"):
            subnet = obj.get_list("subnet")
            return ipset_from_subnet_tokens(subnet) if subnet else IPSet.v4_universe()
        if atype == "ipprefix":
            ip6 = obj.get("ip6")
            return ipset_from_subnet_tokens([ip6]) if ip6 else IPSet.v6_universe()
        if atype == "iprange":
            start, end = obj.get("start-ip"), obj.get("end-ip")
            if start and end:
                return ipset_from_range(start, end)
            return IPSet.opaque_of(f"incomplete range {obj.name}", family)
        if atype == "interface-subnet":
            resolved = self._interface_subnet(vdom, obj.get("interface"))
            if resolved is not None:
                return resolved
            return IPSet.opaque_of(f"subnet of {obj.get('interface') or obj.name}", family)
        if atype in _OPAQUE_ADDR_TYPES:
            detail = obj.get("fqdn") or obj.get("country") or obj.name
            return IPSet.opaque_of(f"{atype}:{detail}", family)
        return IPSet.opaque_of(f"{atype}:{obj.name}", family)

    def _interface_subnet(self, vdom: str, ifname: Optional[str]) -> Optional[IPSet]:
        if not ifname:
            return None
        iface = self.find(vdom, "system interface", ifname)
        if iface is None:
            iface = self.find(GLOBAL_VDOM, "system interface", ifname)
        if iface is None:
            return None
        ip = iface.get_list("ip")
        if len(ip) >= 2 and ip[0] != "0.0.0.0":
            return ipset_from_subnet_tokens(ip)
        return None

    def vip_info(self, vdom: str, name: str) -> Optional[VipInfo]:
        key = (vdom, name)
        if key in self._vip_cache:
            return self._vip_cache[key]
        vip = self.find(vdom, "firewall vip", name) or self.find(vdom, "firewall vip6", name)
        info = self._build_vip(vdom, vip) if vip is not None else None
        self._vip_cache[key] = info
        return info

    def _build_vip(self, vdom: str, vip: ConfigObject) -> VipInfo:
        kind = vip.lower("type", "static-nat")
        extips = vip.get_list("extip")
        external = IPSet.empty()
        for spec in extips:
            external = external.union(ipset_from_spec(spec))
        if not extips:
            external = IPSet.opaque_of(f"vip:{vip.name}")

        mapped = IPSet.empty()
        mapped_text_parts: list[str] = []
        mapped_ports = parse_port_intervals(vip.get_list("mappedport"))
        for spec in vip.get_list("mappedip"):
            mapped = mapped.union(ipset_from_spec(spec))
            mapped_text_parts.append(spec)
        for real in vip.child("realservers"):
            ip = real.get("ip")
            if ip:
                mapped = mapped.union(ipset_from_spec(ip))
                mapped_text_parts.append(ip)
            port = real.get("port")
            if port:
                mapped_ports = mapped_ports.union(parse_port_intervals([port]))
        mapped_addr = vip.get("mapped-addr")
        if mapped_addr:
            mapped = mapped.union(self.resolve_addr(vdom, mapped_addr))
            mapped_text_parts.append(mapped_addr)

        portforward = vip.flag("portforward", False) or kind == "server-load-balance"
        return VipInfo(
            name=vip.name,
            vdom=vip.vdom,
            kind=kind,
            external=external,
            external_text=",".join(extips) or "?",
            mapped=mapped,
            mapped_text=",".join(mapped_text_parts) or "?",
            extintf=(vip.get("extintf") or "any"),
            portforward=portforward,
            protocol=vip.lower("protocol", "tcp"),
            ext_ports=parse_port_intervals(vip.get_list("extport")),
            mapped_ports=mapped_ports,
            source_filter=tuple(vip.get_list("src-filter")),
            enabled=vip.lower("status", "enable") != "disable",
            obj=vip,
        )

    def vips(self, vdom: str) -> dict[str, VipInfo]:
        out: dict[str, VipInfo] = {}
        for section in ("firewall vip", "firewall vip6"):
            for obj in self.model.local_objects(section, vdom):
                if obj.name:
                    info = self.vip_info(vdom, obj.name)
                    if info is not None:
                        out[obj.name] = info
        return out

    def expand_vips(self, vdom: str, names: list[str],
                    _seen: Optional[set[str]] = None) -> tuple[list[VipInfo], bool]:
        seen = _seen if _seen is not None else set()
        found: list[VipInfo] = []
        plain = False
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            info = self.vip_info(vdom, name)
            if info is not None:
                found.append(info)
                continue
            grp = self.find(vdom, "firewall vipgrp", name) or self.find(vdom, "firewall vipgrp6", name)
            if grp is not None:
                sub, sub_plain = self.expand_vips(vdom, grp.get_list("member"), seen)
                found.extend(sub)
                plain = plain or sub_plain
                continue
            plain = True
        return found, plain

    def resolve_service(self, vdom: str, name: str,
                        _stack: tuple[str, ...] = ()) -> ServiceSet:
        if name.upper() == "ALL":
            return ServiceSet.all()
        if name in _stack:
            self.cycles.append(" -> ".join(_stack + (name,)))
            return ServiceSet.opaque_of(f"group loop at {name}")
        cache_key = (vdom, name)
        if not _stack and cache_key in self._svc_cache:
            return self._svc_cache[cache_key]

        result: Optional[ServiceSet] = None
        obj = self.find(vdom, "firewall service custom", name)
        if obj is not None:
            result = self._resolve_service_object(obj)
        if result is None:
            grp = self.find(vdom, "firewall service group", name)
            if grp is not None:
                acc = ServiceSet.empty()
                for m in grp.get_list("member"):
                    acc = acc.union(self.resolve_service(vdom, m, _stack + (name,)))
                result = acc
        if result is None and name.upper() in BUILTIN_SERVICES:
            result = BUILTIN_SERVICES[name.upper()]
        if result is None:
            self.unresolved.add(name)
            result = ServiceSet.opaque_of(f"unknown service {name}")

        if not _stack:
            self._svc_cache[cache_key] = result
        return result

    def _resolve_service_object(self, obj: ConfigObject) -> ServiceSet:
        proto = obj.lower("protocol", "tcp/udp/sctp").upper()
        if proto == "IP":
            number = obj.get("protocol-number") or "0"
            try:
                p = int(number)
            except ValueError:
                return ServiceSet.opaque_of(f"service {obj.name}")
            if p == 0:
                return ServiceSet.all()
            return ServiceSet(ip_proto=IntervalSet.closed(p, p))
        if proto in ("ICMP", "ICMP6"):
            icmptype = obj.get("icmptype")
            if proto == "ICMP6":
                return ServiceSet(ip_proto=IntervalSet.closed(58, 58))
            if icmptype:
                try:
                    t = int(icmptype)
                    return ServiceSet(icmp=IntervalSet.closed(t, t))
                except ValueError:
                    pass
            return ServiceSet(icmp=IntervalSet.closed(0, 255))
        ss = ServiceSet(
            tcp=parse_port_intervals(obj.get_list("tcp-portrange")),
            udp=parse_port_intervals(obj.get_list("udp-portrange")),
            sctp=parse_port_intervals(obj.get_list("sctp-portrange")),
        )
        if ss.is_empty():
            return ServiceSet.opaque_of(f"service {obj.name}")
        return ss

    def resolve_service_list(self, vdom: str, names: list[str]) -> ServiceSet:
        if not names:
            return ServiceSet.all()
        acc = ServiceSet.empty()
        for n in names:
            acc = acc.union(self.resolve_service(vdom, n))
        return acc

    def sdwan_zones(self, vdom: str) -> dict[str, list[str]]:
        cached = self._zone_cache.get(vdom)
        if cached is not None:
            return cached
        zones: dict[str, list[str]] = {}
        for sd in self.model.objects("system sdwan", vdom):
            names = {z.name for z in sd.child("zone")} | {"virtual-wan-link"}
            for zone in names:
                zones.setdefault(zone, [])
            for m in sd.child("members"):
                ifname = m.get("interface")
                if ifname:
                    zones.setdefault(m.get("zone") or "virtual-wan-link", []).append(ifname)
        for vwl in self.model.objects("system virtual-wan-link", vdom):
            members = [m.get("interface") for m in vwl.child("members") if m.get("interface")]
            zones.setdefault("virtual-wan-link", []).extend(members)
        if not any(zones.values()):
            zones = {}
        self._zone_cache[vdom] = zones
        return zones

    def zone_members(self, vdom: str, name: str) -> Optional[list[str]]:
        zone = self.find(vdom, "system zone", name)
        if zone is not None:
            return zone.get_list("interface")
        members = self.sdwan_zones(vdom).get(name)
        return members if members else None

    def resolve_intf(self, vdom: str, names: list[str]) -> InterfaceSet:
        acc = InterfaceSet.of([])
        for n in names:
            if n.lower() == "any":
                return InterfaceSet.any()
            members = self.zone_members(vdom, n)
            acc = acc.union(InterfaceSet.of(members if members else [n]))
        return acc

    def policy_profiles(self, pol: ConfigObject) -> tuple[dict[str, str], Optional[str]]:
        source: Optional[ConfigObject] = pol
        if pol.lower("profile-type") == "group":
            group_name = pol.get("profile-group") or ""
            source = self.find(pol.vdom, "firewall profile-group", group_name)
            if source is None:
                return ({"profile-group": group_name} if group_name else {}), None
        profiles = {}
        for key in PROFILE_KEYS:
            val = source.get(key)
            if val and val != "no-inspection":
                profiles[key] = val
        return profiles, source.get("ssl-ssh-profile")

    def _address_side(self, pol: ConfigObject, key: str, table_family: str
                      ) -> tuple[IPSet, bool, tuple[str, ...]]:
        vdom = pol.vdom
        names = pol.get_list(key)
        names6 = pol.get_list(f"{key}6")
        negate = pol.flag(f"{key}-negate", False)
        negate6 = pol.flag(f"{key}6-negate", negate)
        if table_family == V6:
            v4_names, v6_names = [], names + names6
            negate6 = negate
        else:
            v4_names, v6_names = names, names6

        result = IPSet.empty()
        display: list[str] = []
        for family, group, neg in ((V4, v4_names, negate), (V6, v6_names, negate6)):
            if not group:
                continue
            part = IPSet.empty()
            for n in group:
                part = part.union(self.resolve_addr(vdom, n, family))
            shown = ipset_to_strings(part, limit=4)
            if neg:
                part = part.complement({family})
                display.append("everything except " + ", ".join(shown))
            else:
                display.extend(shown)
            result = result.union(part)
        return result, (negate and bool(v4_names)) or (negate6 and bool(v6_names)), tuple(display)

    def _isdb_side(self, pol: ConfigObject, keys: tuple[str, ...], family: str) -> IPSet:
        acc = IPSet.empty()
        for key in keys:
            for name in pol.get_list(key):
                acc = acc.union(IPSet.opaque_of(f"internet service {name}", family))
        return acc

    def effective_policy(self, pol: ConfigObject, table_family: str = V4) -> EffectivePolicy:
        vdom = pol.vdom
        src_ip, src_neg, src_display = self._address_side(pol, "srcaddr", table_family)
        dst_ip, dst_neg, dst_display = self._address_side(pol, "dstaddr", table_family)

        uses_isdb = False
        if pol.flag("internet-service-src", False):
            uses_isdb = True
            isdb = self._isdb_side(pol, ISDB_SRC_KEYS, V4)
            src_ip = isdb if src_ip.is_empty() else IPSet(
                src_ip.v4, src_ip.v6, src_ip.opaque | isdb.opaque, True)
            src_display = tuple(sorted(t.split("|", 1)[1] for t in isdb.opaque)) or src_display
        if pol.flag("internet-service", False):
            uses_isdb = True
            isdb = self._isdb_side(pol, ISDB_DST_KEYS, V4)
            dst_ip = isdb if dst_ip.is_empty() else IPSet(
                dst_ip.v4, dst_ip.v6, dst_ip.opaque | isdb.opaque, True)
            dst_display = tuple(sorted(t.split("|", 1)[1] for t in isdb.opaque)) or dst_display

        service_names = pol.get_list("service")
        if service_names:
            service = self.resolve_service_list(vdom, service_names)
        elif uses_isdb and pol.flag("internet-service", False):
            service = ServiceSet.opaque_of("ports defined by the internet service")
        else:
            service = ServiceSet.all()
        svc_neg = pol.flag("service-negate", False)
        if svc_neg:
            service = service.complement()

        profiles, ssl_profile = self.policy_profiles(pol)
        vips, plain = self.expand_vips(vdom, pol.get_list("dstaddr") + pol.get_list("dstaddr6"))

        return EffectivePolicy(
            policy=pol,
            vdom=vdom,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_intf=self.resolve_intf(vdom, pol.get_list("srcintf")),
            dst_intf=self.resolve_intf(vdom, pol.get_list("dstintf")),
            service=service,
            schedule=(pol.get("schedule") or "always").strip().lower(),
            action=pol.lower("action", "deny"),
            enabled=pol.lower("status", "enable") != "disable",
            profiles=profiles,
            ssl_profile=ssl_profile,
            utm_enabled=pol.lower("utm-status") != "disable",
            vips=tuple(vips),
            dst_has_plain_address=plain or not vips,
            identity=tuple(tuple(sorted(pol.get_list(k))) for k in IDENTITY_KEYS
                           if pol.get_list(k)),
            l7=tuple(tuple(sorted(pol.get_list(k))) for k in L7_KEYS if pol.get_list(k)),
            match_vip=pol.flag("match-vip", False),
            src_negated=src_neg,
            dst_negated=dst_neg,
            service_negated=svc_neg,
            uses_isdb=uses_isdb,
            nat=pol.flag("nat", False),
            src_display=src_display,
            dst_display=dst_display,
        )

    def effective_policies(self, vdom: str) -> list[EffectivePolicy]:
        if vdom not in self._eff_cache:
            out: list[EffectivePolicy] = []
            for section, family in (("firewall policy", V4), ("firewall policy6", V6)):
                for pol in self.model.local_objects(section, vdom):
                    out.append(self.effective_policy(pol, family))
            self._eff_cache[vdom] = out
        return self._eff_cache[vdom]

