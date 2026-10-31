from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Iterator, Optional

from .findings import Finding, IpRef
from .models import ConfigModel, ConfigObject
from .object_resolver import ObjectResolver, SetResolver
from .object_resolver.algebra import V4, V6, IPSet, _int_range_to_cidrs, tag_label

MAX_OBJECTS = 10
MAX_VALUES = 16

_LINE_RE = re.compile(r"\(line (\d+)\)$")
_EDIT_RE = re.compile(r"^(?:config )?(?P<section>[a-z0-9][a-z0-9 +._-]*?) / edit (?P<rest>.+)$")
_POLICY_IDS_RE = re.compile(r"^policy ids[^:]*: (?P<ids>.+)$")
_TRAILING_NOTE_RE = re.compile(r"\s*\([^()]*\)$")

_LITERAL_KEYS = frozenset({
    "ip", "ip6", "ip6-address", "remote-ip", "subnet", "start-ip", "end-ip",
    "extip", "mappedip", "remote-gw", "remote-gw6", "local-gw", "local-gw6",
    "server", "secondary-server", "tertiary-server", "source-ip", "gateway", "dst",
    "startip", "endip", "source-startip", "source-endip", "primary", "secondary",
    "ip6-primary", "ip6-secondary", "fmg", "src-subnet", "dst-subnet",
    "src-start-ip", "src-end-ip", "dst-start-ip", "dst-end-ip",
    "ipv4-trustip", "ipv6-trustip", "ipv4-start-ip", "ipv4-end-ip",
    "dns-server1", "dns-server2", "dns-server3",
    "ipv4-dns-server1", "ipv4-dns-server2", "ipv4-dns-server3",
    "fqdn", "remotegw-ddns",
} | {f"trusthost{i}" for i in range(1, 11)} | {f"ip6-trusthost{i}" for i in range(1, 11)})
_HOSTNAME_KEYS = frozenset({"server", "secondary-server", "tertiary-server", "fqdn",
                            "remotegw-ddns", "fmg"})
_OWN_ADDRESS_KEYS = frozenset({"ip", "ip6", "ip6-address"})
_ADDRESS_NAME_KEYS = (
    "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "source-address", "source-address6",
    "tunnel-ip-pools", "tunnel-ipv6-pools", "mapped-addr", "src-name", "dst-name",
    "src-name6", "dst-name6", "split-tunneling-routing-address",
    "ipv4-split-include", "ipv4-split-exclude", "ipv6-split-include", "ipv6-split-exclude",
)
_GROUP_SECTIONS = frozenset({"firewall addrgrp", "firewall addrgrp6",
                             "firewall vipgrp", "firewall vipgrp6"})
_INTERFACE_KEYS = ("srcintf", "dstintf", "intf", "source-interface", "extintf", "interface",
                   "device", "associated-interface")
_PHASE1_SECTIONS = ("vpn ipsec phase1-interface", "vpn ipsec phase1")
_POLICY_SECTIONS = ("firewall policy", "firewall policy6")


def _written(tokens: Iterable[str]) -> str:
    return " ".join(f'"{t}"' if not t or any(c.isspace() for c in t) else t for t in tokens)


def _is_netmask(token: str) -> bool:
    try:
        n = int(ipaddress.IPv4Address(token))
    except ValueError:
        return False
    inverted = ~n & 0xFFFFFFFF
    return inverted & (inverted + 1) == 0


def _parse_one(token: str) -> Optional[str]:
    try:
        if "-" in token and "/" not in token:
            a, _, b = token.partition("-")
            lo, hi = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
            return f"{lo}-{hi}"
        if "/" in token:
            return str(ipaddress.ip_interface(token))
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def parse_literal(tokens: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(tokens):
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if nxt is not None and "/" not in tokens[i] and _is_netmask(nxt):
            try:
                out.append(str(ipaddress.ip_interface(f"{tokens[i]}/{nxt}")))
                i += 2
                continue
            except ValueError:
                pass
        parsed = _parse_one(tokens[i])
        if parsed:
            out.append(parsed)
        i += 1
    return out


def _unspecified(value: str) -> bool:
    try:
        return ipaddress.ip_interface(value).ip.is_unspecified
    except ValueError:
        return False


def ipset_values(s: IPSet) -> list[str]:
    out: list[str] = []
    if s.is_v4_universe():
        out.append("0.0.0.0/0")
    else:
        for lo, hi in s.v4.intervals:
            out.extend(_int_range_to_cidrs(lo, hi, 4))
    if s.is_v6_universe():
        out.append("::/0")
    else:
        for lo, hi in s.v6.intervals:
            out.extend(_int_range_to_cidrs(lo, hi, 6))
    out.extend(sorted(tag_label(t) for t in s.opaque))
    return out


def _ref(source: str, setting: str, tokens: list[str], values: list[str], line: int,
         note: str = "") -> IpRef:
    return IpRef(source=source, setting=setting, written=_written(tokens),
                 ips=tuple(values[:MAX_VALUES]), line=line,
                 more=max(0, len(values) - MAX_VALUES), note=note)


def _label(obj: ConfigObject) -> str:
    return f"{obj.section} {obj.name}" if obj.name else obj.section


class IpExtractor:
    def __init__(self, model: ConfigModel, sets: SetResolver, resolver: ObjectResolver) -> None:
        self.model = model
        self.sets = sets
        self.resolver = resolver
        self._by_line: Optional[dict[int, ConfigObject]] = None
        self._own: dict[int, list[IpRef]] = {}
        self._full: dict[int, list[IpRef]] = {}

    def attach(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            f.ips = self.for_finding(f)

    def for_finding(self, finding: Finding) -> list[IpRef]:
        objects: list[ConfigObject] = []
        seen: set[int] = set()
        for line in finding.evidence:
            for obj in self._objects_in(line, finding.vdom):
                if id(obj) not in seen:
                    seen.add(id(obj))
                    objects.append(obj)
        rows: list[IpRef] = []
        keys: set[tuple[str, str, int]] = set()
        for obj in objects[:MAX_OBJECTS]:
            for ref in self._rows(obj):
                key = (ref.source, ref.setting, ref.line)
                if key not in keys:
                    keys.add(key)
                    rows.append(ref)
        return rows

    def _line_index(self) -> dict[int, ConfigObject]:
        if self._by_line is None:
            index: dict[int, ConfigObject] = {}

            def walk(obj: ConfigObject) -> None:
                if obj.line:
                    index.setdefault(obj.line, obj)
                for children in obj.children.values():
                    for child in children:
                        walk(child)

            for obj in self.model.iter_all():
                walk(obj)
            self._by_line = index
        return self._by_line

    def _objects_in(self, line: str, vdom: str) -> Iterator[ConfigObject]:
        text = line.strip()
        m = _POLICY_IDS_RE.match(text)
        if m:
            for pid in m.group("ids").split(","):
                pol = self._find_any(vdom, _POLICY_SECTIONS, pid.strip())
                if pol is not None:
                    yield pol
            return
        if not (text.startswith("config ") or " / edit " in text):
            return
        lm = _LINE_RE.search(text)
        if lm:
            obj = self._line_index().get(int(lm.group(1)))
            if obj is not None:
                yield obj
                return
        m = _EDIT_RE.match(text)
        if not m:
            return
        section, rest = m.group("section"), m.group("rest")
        while rest:
            obj = self._find(vdom, section, rest)
            if obj is not None:
                yield obj
                return
            trimmed = _TRAILING_NOTE_RE.sub("", rest)
            if trimmed == rest:
                return
            rest = trimmed

    def _find(self, vdom: str, section: str, name: str) -> Optional[ConfigObject]:
        if section == "system interface":
            obj = self.resolver.interface(name)
            if obj is not None:
                return obj
        return self.sets.find(vdom, section, name)

    def _find_any(self, vdom: str, sections: Iterable[str], name: str) -> Optional[ConfigObject]:
        for section in sections:
            obj = self.sets.find(vdom, section, name)
            if obj is not None:
                return obj
        return None

    def _rows(self, obj: ConfigObject) -> list[IpRef]:
        cached = self._full.get(id(obj))
        if cached is not None:
            return cached
        rows = list(self._own_rows(obj))
        for related in self._related(obj):
            rows.extend(self._own_rows(related))
        parent = obj.get("phase1name")
        if parent:
            p1 = self._find_any(obj.vdom, _PHASE1_SECTIONS, parent)
            if p1 is not None and p1 is not obj:
                rows.extend(self._rows(p1))
        self._full[id(obj)] = rows
        return rows

    def _related(self, obj: ConfigObject) -> Iterator[ConfigObject]:
        vdom = obj.vdom
        if obj.section != "system interface":
            for key in _INTERFACE_KEYS:
                for name in obj.get_list(key):
                    if name.lower() == "any":
                        continue
                    for member in self.sets.zone_members(vdom, name) or [name]:
                        itf = self.resolver.interface(member)
                        if itf is not None:
                            yield itf
        dst = obj.get_list("dstaddr") + obj.get_list("dstaddr6")
        if dst:
            vips, _plain = self.sets.expand_vips(vdom, dst)
            for vip in vips:
                yield vip.obj

    def _own_rows(self, obj: ConfigObject) -> list[IpRef]:
        cached = self._own.get(id(obj))
        if cached is not None:
            return cached
        rows = self._object_rows(obj, _label(obj), top=True)
        if obj.section == "system interface" and not any(r.setting == "ip" for r in rows):
            mode = obj.lower("mode")
            if mode in ("dhcp", "pppoe"):
                rows.append(IpRef(source=_label(obj), setting="mode", written=mode, ips=(),
                                  line=obj.line,
                                  note=f"the address is assigned by {mode.upper()} at runtime "
                                       f"and isn't in the config"))
        self._own[id(obj)] = rows
        return rows

    def _object_rows(self, obj: ConfigObject, label: str, top: bool) -> list[IpRef]:
        rows: list[IpRef] = []
        for key, tokens in obj.settings.items():
            if key in _LITERAL_KEYS:
                values = parse_literal(tokens)
                if key in _OWN_ADDRESS_KEYS:
                    values = [v for v in values if not _unspecified(v)]
                if values:
                    rows.append(_ref(label, key, tokens, values, obj.line))
                elif key in _HOSTNAME_KEYS and tokens:
                    rows.append(_ref(label, key, tokens, [], obj.line,
                                     note="a name, not an IP address; it's resolved at runtime"))
        name_keys = list(_ADDRESS_NAME_KEYS)
        if top and obj.section in _GROUP_SECTIONS:
            name_keys += ["member", "exclude-member"]
        for key in name_keys:
            names = obj.get_list(key)
            if not names:
                continue
            family = V6 if key.endswith("6") or obj.section.endswith("6") else V4
            resolved = IPSet.empty()
            for name in names:
                resolved = resolved.union(self.sets.resolve_addr(obj.vdom, name, family))
            values = ipset_values(resolved)
            if not values:
                continue
            note = (f"{key}-negate is enabled, so the rule matches everything except these"
                    if obj.flag(f"{key}-negate", False) else "")
            rows.append(_ref(label, key, names, values, obj.line, note))
        for sub, children in obj.children.items():
            for child in children:
                child_label = f"{label} > {sub}" + (f" {child.name}" if child.name else "")
                rows.extend(self._object_rows(child, child_label, top=False))
        return rows


def attach_ips(findings: Iterable[Finding], model: ConfigModel, sets: SetResolver,
               resolver: ObjectResolver) -> None:
    IpExtractor(model, sets, resolver).attach(findings)
