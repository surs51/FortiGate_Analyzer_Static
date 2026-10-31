from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ConfigModel, ConfigObject

ADDRESS = "address"
SERVICE = "service"
VIP = "vip"
IPPOOL = "ippool"

_POLICY_ADDR = ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "srcaddr4", "dstaddr4",
                "ztna-ems-tag", "ztna-geo-tag")


@dataclass(frozen=True)
class DomainSpec:
    key: str
    label: str
    sections: tuple[str, ...]
    addr_fields: tuple[str, ...] = ()
    svc_fields: tuple[str, ...] = ()
    pool_fields: tuple[str, ...] = ()
    member_kind: str | None = None
    addr_is_vip: bool = False
    child_path: tuple[str, ...] = ()


DOMAINS: tuple[DomainSpec, ...] = (
    DomainSpec("firewall_policy", "Firewall policy",
               ("firewall policy", "firewall policy6"),
               addr_fields=_POLICY_ADDR, svc_fields=("service",),
               pool_fields=("poolname", "poolname6"), addr_is_vip=True),
    DomainSpec("security_policy", "NGFW security policy",
               ("firewall security-policy",),
               addr_fields=_POLICY_ADDR, svc_fields=("service",)),
    DomainSpec("proxy_policy", "Proxy policy",
               ("firewall proxy-policy",),
               addr_fields=_POLICY_ADDR, svc_fields=("service",),
               pool_fields=("poolname",), addr_is_vip=True),
    DomainSpec("dos_policy", "DoS policy",
               ("firewall dos-policy", "firewall dos-policy6"),
               addr_fields=("srcaddr", "dstaddr"), svc_fields=("service",),
               addr_is_vip=True),
    DomainSpec("central_snat", "Central SNAT map",
               ("firewall central-snat-map",),
               addr_fields=("orig-addr", "dst-addr", "orig-addr6", "dst-addr6"),
               pool_fields=("nat-ippool", "nat-ippool6")),
    DomainSpec("multicast_policy", "Multicast policy",
               ("firewall multicast-policy", "firewall multicast-policy6"),
               addr_fields=("srcaddr", "dstaddr")),
    DomainSpec("local_in_policy", "Local-in policy",
               ("firewall local-in-policy", "firewall local-in-policy6"),
               addr_fields=("srcaddr", "dstaddr"), svc_fields=("service",)),
    DomainSpec("interface_policy", "Interface policy",
               ("firewall interface-policy", "firewall interface-policy6"),
               addr_fields=("srcaddr", "dstaddr", "srcaddr6", "dstaddr6"),
               svc_fields=("service",)),
    DomainSpec("shaping_policy", "Traffic shaping policy",
               ("firewall shaping-policy",),
               addr_fields=("srcaddr", "dstaddr", "srcaddr6", "dstaddr6"),
               svc_fields=("service",)),
    DomainSpec("acl", "Hardware ACL",
               ("firewall acl", "firewall acl6"),
               addr_fields=("srcaddr", "dstaddr"), svc_fields=("service",)),
    DomainSpec("ttl_policy", "TTL policy",
               ("firewall ttl-policy",),
               addr_fields=("srcaddr",), svc_fields=("service",)),
    DomainSpec("static_route", "Static route",
               ("router static", "router static6"),
               addr_fields=("dstaddr",)),
    DomainSpec("policy_route", "Policy route",
               ("router policy", "router policy6"),
               addr_fields=("srcaddr", "dstaddr")),
    DomainSpec("phase1_split", "IPsec tunnel settings",
               ("vpn ipsec phase1-interface",),
               addr_fields=("ipv4-split-include", "ipv4-split-exclude",
                            "ipv6-split-include", "ipv6-split-exclude",
                            "ipv4-name", "ipv6-name")),
    DomainSpec("phase2_selector", "IPsec phase 2 selector",
               ("vpn ipsec phase2-interface", "vpn ipsec phase2"),
               addr_fields=("src-name", "dst-name", "src-name6", "dst-name6")),
    DomainSpec("sslvpn_settings", "SSL-VPN settings",
               ("vpn ssl settings",),
               addr_fields=("source-address", "source-address6",
                            "tunnel-ip-pools", "tunnel-ipv6-pools")),
    DomainSpec("sslvpn_auth_rule", "SSL-VPN authentication rule",
               ("vpn ssl settings",),
               addr_fields=("source-address", "source-address6"),
               child_path=("authentication-rule",)),
    DomainSpec("sslvpn_portal", "SSL-VPN portal",
               ("vpn ssl web portal",),
               addr_fields=("ip-pools", "ipv6-pools", "split-tunneling-routing-address",
                            "ipv6-split-tunneling-routing-address")),
    DomainSpec("ssl_exempt", "SSL inspection exemption",
               ("firewall ssl-ssh-profile",),
               addr_fields=("address", "address6", "wildcard-fqdn"),
               child_path=("ssl-exempt",)),
    DomainSpec("auth_rule", "Authentication rule",
               ("authentication rule",),
               addr_fields=("srcaddr", "dstaddr", "srcaddr6", "dstaddr6")),
    DomainSpec("exempt_list", "Security exempt list",
               ("user security-exempt-list",),
               addr_fields=("srcaddr", "dstaddr"), svc_fields=("service",),
               child_path=("rule",)),
    DomainSpec("vip_address", "VIP address reference",
               ("firewall vip", "firewall vip6"),
               addr_fields=("mapped-addr", "extaddr")),
    DomainSpec("vipgrp", "VIP group",
               ("firewall vipgrp", "firewall vipgrp6"),
               member_kind=VIP),
    DomainSpec("addrgrp", "Address group",
               ("firewall addrgrp", "firewall addrgrp6"),
               member_kind=ADDRESS),
    DomainSpec("addrgrp_exclude", "Address group exclusion",
               ("firewall addrgrp", "firewall addrgrp6"),
               addr_fields=("exclude-member",)),
    DomainSpec("svcgrp", "Service group",
               ("firewall service group",),
               member_kind=SERVICE),
    DomainSpec("sdwan_service", "SD-WAN rule",
               ("system sdwan", "system virtual-wan-link"),
               addr_fields=("dst", "src", "dst6", "src6"),
               child_path=("service",)),
)

UNMODELED_REFERENCE_SECTIONS: dict[str, str] = {
    "ztna traffic-forward-proxy": "ZTNA traffic-forward proxy",
    "ztna web-proxy": "ZTNA web proxy",
    "firewall access-proxy": "Access proxy (ZTNA)",
    "firewall access-proxy6": "Access proxy (ZTNA, IPv6)",
    "wireless-controller vap": "Wireless SSIDs",
}


@dataclass
class ReferenceIndex:
    _refs: dict[str, dict[tuple[str, str], set[str]]] = field(default_factory=dict)
    domains_present: set[str] = field(default_factory=set)
    domain_counts: dict[str, int] = field(default_factory=dict)

    def _bucket(self, kind: str) -> dict[tuple[str, str], set[str]]:
        return self._refs.setdefault(kind, {})

    def add(self, kind: str, vdom: str, name: str, domain_key: str) -> None:
        name = name.strip().strip('"')
        if not name:
            return
        self._bucket(kind).setdefault((vdom, name), set()).add(domain_key)

    def is_referenced(self, kind: str, vdom: str, name: str) -> bool:
        return (vdom, name) in self._bucket(kind)

    def referencing_domains(self, kind: str, vdom: str, name: str) -> set[str]:
        return set(self._bucket(kind).get((vdom, name), set()))

    def used_set(self, kind: str) -> set[tuple[str, str]]:
        return set(self._bucket(kind).keys())


def _descend(obj: ConfigObject, path: tuple[str, ...]) -> list[ConfigObject]:
    level = [obj]
    for step in path:
        level = [c for o in level for c in o.child(step)]
    return level


def build_reference_index(model: ConfigModel) -> ReferenceIndex:
    idx = ReferenceIndex()
    by_section: dict[str, list[DomainSpec]] = {}
    for spec in DOMAINS:
        for sec in spec.sections:
            by_section.setdefault(sec, []).append(spec)

    for obj in model.iter_all():
        specs = by_section.get(obj.section.lower())
        if not specs:
            continue
        for spec in specs:
            targets = _descend(obj, spec.child_path) if spec.child_path else [obj]
            if not targets:
                continue
            idx.domains_present.add(spec.key)
            idx.domain_counts[spec.key] = idx.domain_counts.get(spec.key, 0) + len(targets)
            for target in targets:
                _index_one(idx, spec, obj.vdom, target)
    return idx


def _index_one(idx: ReferenceIndex, spec: DomainSpec, vdom: str, obj: ConfigObject) -> None:
    if spec.member_kind:
        for m in obj.get_list("member"):
            idx.add(spec.member_kind, vdom, m, spec.key)
        return
    for fld in spec.addr_fields:
        for name in obj.get_list(fld):
            idx.add(ADDRESS, vdom, name, spec.key)
            if spec.addr_is_vip:
                idx.add(VIP, vdom, name, spec.key)
    for fld in spec.svc_fields:
        for name in obj.get_list(fld):
            idx.add(SERVICE, vdom, name, spec.key)
    for fld in spec.pool_fields:
        for name in obj.get_list(fld):
            idx.add(IPPOOL, vdom, name, spec.key)


def present_unmodeled_sections(model: ConfigModel) -> list[str]:
    seen_sections = {o.section.lower() for o in model.iter_all()}
    return [label for sec, label in UNMODELED_REFERENCE_SECTIONS.items()
            if sec in seen_sections]
