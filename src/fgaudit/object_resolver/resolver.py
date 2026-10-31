from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..knowledge import SSL_BUILTIN_DEPTH, WAN_NAME_RE, is_public_address
from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigModel, ConfigObject
from .effective import SetResolver
from .reference_index import (
    ADDRESS,
    IPPOOL,
    SERVICE,
    VIP,
    ReferenceIndex,
    build_reference_index,
)

logger = logging.getLogger(__name__)

INDETERMINATE_ADDR_TYPES = {
    "fqdn", "wildcard-fqdn", "geography", "dynamic", "mac",
    "interface-subnet", "wildcard", "sdn", "route-tag", "template",
}
_NON_LINK_TYPES = {"loopback", "tunnel", "vdom-link", "vap-switch", "wl-mesh",
                   "ssl", "switch-vlan"}
_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass(slots=True)
class _AddrInfo:
    is_all: bool
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    is_rfc1918: bool = False
    kind: str = "subnet"
    indeterminate: bool = False


@dataclass(slots=True)
class WanSignal:
    confidence: str
    reason: str


class ObjectResolver:
    def __init__(self, model: ConfigModel, wan_interfaces: Optional[Iterable[str]] = None,
                 sets: Optional[SetResolver] = None):
        self.model = model
        self.sets = sets or SetResolver(model)
        self.wan_override: set[str] = {w.strip().strip('"') for w in (wan_interfaces or [])}
        self._iface: dict[str, ConfigObject] = {}
        self._iface_role: dict[str, str] = {}
        self._signals: dict[str, list[WanSignal]] = {}
        self._addr: dict[str, dict[str, _AddrInfo]] = {}
        self._zone: dict[str, dict[str, list[str]]] = {}
        self._vip: dict[str, set[str]] = {}
        self._ippool: dict[str, set[str]] = {}
        self._ssl: dict[str, dict[str, str]] = {}
        self._dialup_tunnels: set[str] = set()
        self._site_tunnels: set[str] = set()
        self.reference_index: ReferenceIndex = ReferenceIndex()
        self.used_addresses: set[tuple[str, str]] = set()
        self.used_services: set[tuple[str, str]] = set()
        self.used_vips: set[tuple[str, str]] = set()
        self.used_ippools: set[tuple[str, str]] = set()
        self._strong_cache: Optional[bool] = None
        self._wan_cache: Optional[set[str]] = None
        self._build()

    def _add_signal(self, iface: str, confidence: str, reason: str) -> None:
        name = iface.strip().strip('"')
        if name:
            self._signals.setdefault(name, []).append(WanSignal(confidence, reason))

    def _build(self) -> None:
        routes: list[ConfigObject] = []
        for obj in self.model.iter_all():
            sec = obj.section
            if sec == "system interface" and obj.name:
                self._index_interface(obj)
            elif sec == "system zone":
                self._zone.setdefault(obj.vdom, {})[obj.name] = obj.get_list("interface")
            elif sec in ("firewall address", "firewall address6"):
                self._addr.setdefault(obj.vdom, {})[obj.name] = self._addr_info(obj)
            elif sec in ("firewall vip", "firewall vip6", "firewall vipgrp", "firewall vipgrp6"):
                self._vip.setdefault(obj.vdom, set()).add(obj.name)
            elif sec == "firewall ippool":
                self._ippool.setdefault(obj.vdom, set()).add(obj.name)
            elif sec == "firewall ssl-ssh-profile":
                self._ssl.setdefault(obj.vdom, {})[obj.name] = self._ssl_depth_obj(obj)
            elif sec in ("router static", "router static6"):
                routes.append(obj)
            elif sec in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
                if obj.lower("type", "static") == "dynamic":
                    self._dialup_tunnels.add(obj.name)
                else:
                    self._site_tunnels.add(obj.name)

        for route in routes:
            self._index_default_route(route)
        self._index_sdwan_members()

        self.reference_index = build_reference_index(self.model)
        self.used_addresses = self.reference_index.used_set(ADDRESS)
        self.used_services = self.reference_index.used_set(SERVICE)
        self.used_vips = self.reference_index.used_set(VIP)
        self.used_ippools = self.reference_index.used_set(IPPOOL)

    def _index_interface(self, obj: ConfigObject) -> None:
        name = obj.name
        self._iface[name] = obj
        self._iface_role[name] = obj.lower("role", "undefined") or "undefined"
        itype = obj.lower("type")
        mode = obj.lower("mode", "static")
        if mode in ("dhcp", "pppoe") and obj.flag("defaultgw", True):
            self._add_signal(name, "high",
                             f"gets its default route from the provider ({mode.upper()})")
        ip = obj.get("ip")
        if ip and itype not in _NON_LINK_TYPES and is_public_address(ip):
            self._add_signal(name, "medium", f"has a public address ({ip})")

    def _index_default_route(self, route: ConfigObject) -> None:
        dst = route.text("dst").strip()
        if route.get_list("dstaddr") or route.get_list("internet-service"):
            return
        if dst not in ("", "0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0"):
            return
        if route.flag("blackhole", False) or route.lower("status", "enable") == "disable":
            return
        device = route.get("device")
        if device:
            self._add_signal(device, "high", "carries the default route")
        zones = route.get_list("sdwan-zone")
        if route.flag("virtual-wan-link", False) or route.flag("sdwan", False):
            zones = zones + ["virtual-wan-link"]
        for zone in zones:
            for member in self.sets.sdwan_zones(route.vdom).get(zone, []):
                self._add_signal(member, "high", f"carries the default route through SD-WAN zone {zone}")

    def _index_sdwan_members(self) -> None:
        for vdom in set(self.model.vdoms) | {ROOT_VDOM}:
            for zone, members in self.sets.sdwan_zones(vdom).items():
                for member in members:
                    itype = self._iface[member].lower("type") if member in self._iface else ""
                    if itype == "tunnel" or member in self._site_tunnels:
                        continue
                    self._add_signal(member, "medium", f"is an SD-WAN member link (zone {zone})")

    @staticmethod
    def _addr_info(obj: ConfigObject) -> _AddrInfo:
        atype = obj.lower("type")
        if obj.name.lower() == "all":
            return _AddrInfo(True, [], False, "all", False)
        if atype in INDETERMINATE_ADDR_TYPES:
            return _AddrInfo(False, [], False, atype, True)

        networks: list[ipaddress._BaseNetwork] = []
        is_all = False
        rfc1918 = False
        kind = atype or "subnet"
        indeterminate = False

        subnet = obj.get_list("subnet")
        if len(subnet) >= 2:
            try:
                net = ipaddress.ip_network(f"{subnet[0]}/{subnet[1]}", strict=False)
                networks.append(net)
                is_all = net.prefixlen == 0
                rfc1918 = net.is_private and not is_all
                kind = "subnet"
            except ValueError:
                indeterminate = True

        start, end = obj.get("start-ip"), obj.get("end-ip")
        if start and end:
            try:
                a = ipaddress.ip_address(start)
                ipaddress.ip_address(end)
                kind = "iprange"
                rfc1918 = rfc1918 or a.is_private
            except ValueError:
                indeterminate = True

        ip6 = obj.get("ip6")
        if ip6 and "/" in ip6:
            try:
                net6 = ipaddress.ip_network(ip6, strict=False)
                networks.append(net6)
                is_all = is_all or net6.prefixlen == 0
            except ValueError:
                indeterminate = True

        if not networks and kind != "iprange" and not is_all:
            indeterminate = True
        return _AddrInfo(is_all, networks, rfc1918, kind, indeterminate)

    @staticmethod
    def _ssl_depth_obj(obj: ConfigObject) -> str:
        ssl = obj.child_singleton("ssl")
        inspect_all = ssl.lower("inspect-all") if ssl else ""
        if inspect_all == "deep-inspection":
            return "deep"
        if inspect_all == "certificate-inspection":
            return "cert"
        https = obj.child_singleton("https")
        if https is not None:
            status = https.lower("status")
            if status == "deep-inspection":
                return "deep"
            if status == "certificate-inspection":
                return "cert"
            if status == "disable":
                return "none"
        statuses = {c.lower("status") for sub in obj.children.values() for c in sub
                    if c.get("status")}
        if "deep-inspection" in statuses:
            return "deep"
        if "certificate-inspection" in statuses:
            return "cert"
        if statuses:
            return "none"
        return "unknown"

    def _signals_for(self, name: str) -> list[WanSignal]:
        n = name.strip().strip('"')
        out = list(self._signals.get(n, []))
        if n in self.wan_override:
            out.insert(0, WanSignal("high", "was marked as WAN on the command line"))
        if self._iface_role.get(n) == "wan":
            out.insert(0, WanSignal("high", "has role wan"))
        return out

    def has_strong_wan_signals(self) -> bool:
        if self._strong_cache is None:
            self._strong_cache = bool(
                self.wan_override
                or any(r == "wan" for r in self._iface_role.values())
                or any(s.confidence in ("high", "medium")
                       for sigs in self._signals.values() for s in sigs))
        return self._strong_cache

    def wan_confidence_low(self) -> bool:
        return not self.has_strong_wan_signals()

    def interface_is_internet_facing(self, name: str) -> tuple[bool, str]:
        n = name.strip().strip('"')
        signals = self._signals_for(n)
        role = self._iface_role.get(n, "undefined")
        strong = [s for s in signals if s.confidence == "high"]
        if strong:
            return True, "high"
        if role in ("lan", "dmz"):
            return False, "n/a"
        if signals:
            best = max(signals, key=lambda s: _RANK[s.confidence])
            return True, best.confidence
        if not self.has_strong_wan_signals() and WAN_NAME_RE.search(n):
            return True, "low"
        return False, "n/a"

    def wan_reason(self, name: str) -> str:
        signals = self._signals_for(name)
        if signals:
            best = max(signals, key=lambda s: _RANK[s.confidence])
            return best.reason
        if WAN_NAME_RE.search(name):
            return "has a name that looks like an internet link"
        return "is treated as internet-facing"

    def interface_is_published(self, name: str) -> bool:
        target = name.strip().strip('"')
        for vdom in self.model.vdoms:
            for info in self.sets.vips(vdom).values():
                if info.extintf == target:
                    return True
        return False

    @property
    def internet_facing_interfaces(self) -> set[str]:
        if self._wan_cache is not None:
            return self._wan_cache
        names = set(self._iface) | set(self._signals) | set(self.wan_override)
        out = {n for n in names if self.interface_is_internet_facing(n)[0]}
        for vdom in set(self.model.vdoms) | {ROOT_VDOM}:
            for zone, members in self.sets.sdwan_zones(vdom).items():
                if members and any(m in out for m in members):
                    out.add(zone)
            for zone, members in self._zone.get(vdom, {}).items():
                if any(m in out for m in members):
                    out.add(zone)
        self._wan_cache = out
        return out

    def interface_vdom(self, name: str) -> Optional[str]:
        obj = self._iface.get(name)
        if obj is None:
            return None
        return obj.get("vdom") or obj.vdom

    def interface(self, name: str) -> Optional[ConfigObject]:
        return self._iface.get(name)

    def interfaces(self) -> list[ConfigObject]:
        return list(self._iface.values())

    def is_remote_access_interface(self, name: str) -> bool:
        return name.startswith("ssl.") or name in self._dialup_tunnels

    def address_reference_domains(self, vdom: str, name: str) -> set[str]:
        return self.reference_index.referencing_domains(ADDRESS, vdom, name)

    def service_reference_domains(self, vdom: str, name: str) -> set[str]:
        return self.reference_index.referencing_domains(SERVICE, vdom, name)

    def _lookup(self, store: dict, vdom: str, name: str):
        scopes = (vdom, GLOBAL_VDOM) if self.model.multi_vdom else (vdom, GLOBAL_VDOM, ROOT_VDOM)
        for v in scopes:
            bucket = store.get(v)
            if bucket and name in bucket:
                return bucket[name]
        return None

    def address_networks(self, vdom: str, name: str) -> list[ipaddress._BaseNetwork]:
        info = self._lookup(self._addr, vdom, name)
        return list(info.networks) if info else []

    def address_is_rfc1918(self, vdom: str, name: str) -> bool:
        info = self._lookup(self._addr, vdom, name)
        return bool(info and info.is_rfc1918)

    def is_vip(self, vdom: str, name: str) -> bool:
        scopes = (vdom, GLOBAL_VDOM) if self.model.multi_vdom else (vdom, GLOBAL_VDOM, ROOT_VDOM)
        return any(name in self._vip.get(v, set()) for v in scopes)

    def central_nat(self, vdom: str) -> bool:
        settings = self.model.singleton("system settings", vdom)
        return bool(settings) and settings.flag("central-nat", False)

    def ssl_depth(self, vdom: str, name: Optional[str]) -> str:
        if not name:
            return "none"
        depth = self._lookup(self._ssl, vdom, name)
        if depth is not None and depth != "unknown":
            return depth
        if name in SSL_BUILTIN_DEPTH:
            return SSL_BUILTIN_DEPTH[name]
        return depth or "unknown"

    def interface_roles(self, vdom: str, interfaces: Iterable[str]) -> set[str]:
        roles: set[str] = set()
        for itf in interfaces:
            if itf.lower() == "any":
                roles.add("any")
                continue
            members = self.sets.zone_members(vdom, itf) or [itf]
            for m in members:
                roles.add(self._role_of(m))
        return roles or {"undefined"}

    def _role_of(self, name: str) -> str:
        if self.is_remote_access_interface(name):
            return "remote"
        if name in self._site_tunnels:
            return "vpn"
        facing, confidence = self.interface_is_internet_facing(name)
        explicit = self._iface_role.get(name, "undefined")
        if facing and (confidence == "high" or explicit in ("undefined", "wan")):
            return "wan"
        if explicit != "undefined":
            return explicit
        return "undefined"

    def wan_confidence_for(self, vdom: str, interfaces: Iterable[str]) -> str:
        best = "n/a"
        for itf in interfaces:
            if itf.lower() == "any":
                continue
            for m in self.sets.zone_members(vdom, itf) or [itf]:
                facing, conf = self.interface_is_internet_facing(m)
                if facing and _RANK.get(conf, 0) > _RANK.get(best, 0):
                    best = conf
        return best

    @property
    def iface_roles_map(self) -> dict[str, str]:
        return dict(self._iface_role)

    def vips(self, vdom: str) -> set[str]:
        return set(self._vip.get(vdom, set()))

    def ippools(self, vdom: str) -> set[str]:
        return set(self._ippool.get(vdom, set()))

    def addresses(self, vdom: str) -> dict[str, _AddrInfo]:
        return dict(self._addr.get(vdom, {}))

    def zones(self, vdom: str) -> dict[str, list[str]]:
        return dict(self._zone.get(vdom, {}))
