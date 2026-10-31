from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigObject
from ..object_resolver.algebra import (
    V4,
    IntervalSet,
    IPSet,
    ServiceSet,
    ipset_from_spec,
    ipset_to_strings,
)

ADMIN_PROTOCOLS = ("https", "http", "ssh", "telnet", "snmp")
AUX_PROTOCOLS = ("fgfm", "fabric", "speed-test")


@dataclass
class ServiceExposure:
    interface: str
    vdom: str
    protocol: str
    wan: bool
    wan_confidence: str
    sources: IPSet
    local_in_rules: tuple[str, ...]

    @property
    def unreachable(self) -> bool:
        return self.sources.is_empty() and not self.sources.inexact

    @property
    def unrestricted(self) -> bool:
        return self.sources.is_v4_universe() or self.sources.v4_count() >= (1 << 31)

    def sources_text(self) -> str:
        return ", ".join(ipset_to_strings(self.sources, limit=5))


def global_settings(ctx) -> Optional[ConfigObject]:
    return (ctx.model.singleton("system global", GLOBAL_VDOM)
            or ctx.model.singleton("system global", ROOT_VDOM)
            or ctx.model.first("system global"))


def _port(g: Optional[ConfigObject], key: str, default: int) -> int:
    try:
        return int(g.get(key)) if g and g.get(key) else default
    except ValueError:
        return default


def protocol_services(ctx) -> dict[str, Optional[ServiceSet]]:
    g = global_settings(ctx)

    def tcp(p: int) -> ServiceSet:
        return ServiceSet(tcp=IntervalSet.closed(p, p))

    return {
        "https": tcp(_port(g, "admin-sport", 443)),
        "http": tcp(_port(g, "admin-port", 80)),
        "ssh": tcp(_port(g, "admin-ssh-port", 22)),
        "telnet": tcp(_port(g, "admin-telnet-port", 23)),
        "snmp": ServiceSet(udp=IntervalSet.closed(161, 161)),
        "fgfm": tcp(541),
        "fabric": tcp(8013),
        "speed-test": None,
    }


def _interface_address(ctx, iface: str) -> Optional[IPSet]:
    obj = ctx.resolver.interface(iface)
    ip = obj.get("ip") if obj else None
    if not ip or ip.startswith("0.0.0.0"):
        return None
    return ipset_from_spec(ip.split("/")[0])


def _deny_applies(ctx, vdom: str, rule: ConfigObject, iface: str) -> bool:
    dsts = rule.get_list("dstaddr")
    if not dsts or any(d.lower() == "all" for d in dsts):
        return True
    own = _interface_address(ctx, iface)
    if own is None:
        return False
    dst = IPSet.empty()
    for name in dsts:
        dst = dst.union(ctx.sets.resolve_addr(vdom, name, V4))
    return dst.covers(own)


def reachable_sources(ctx, vdom: str, iface: str,
                      service: Optional[ServiceSet]) -> tuple[IPSet, tuple[str, ...]]:
    residual = IPSet.v4_universe()
    exposed = IPSet.empty()
    used: list[str] = []
    if service is None:
        return residual, ()
    for rule in (o for o in ctx.model.local_objects("firewall local-in-policy", vdom) if o.name):
        if rule.lower("status", "enable") == "disable":
            continue
        intfs = rule.get_list("intf")
        if intfs and "any" not in [i.lower() for i in intfs]:
            members = set()
            for name in intfs:
                members.update(ctx.sets.zone_members(vdom, name) or [name])
            if iface not in members:
                continue
        rule_svc = ctx.sets.resolve_service_list(vdom, rule.get_list("service"))
        if not rule_svc.overlaps(service):
            continue
        src = IPSet.empty()
        for name in rule.get_list("srcaddr") or ["all"]:
            src = src.union(ctx.sets.resolve_addr(vdom, name, V4))
        if rule.flag("srcaddr-negate", False):
            src = src.complement({V4})
        if rule.lower("action", "deny") == "accept":
            gained = src if (residual.is_universe() or src.has_opaque() or src.inexact) \
                else residual.intersection(src)
            exposed = exposed.union(gained)
            residual = residual.minus(src)
            used.append(rule.name)
        elif rule_svc.covers(service) and _deny_applies(ctx, vdom, rule, iface):
            residual = residual.minus(src)
            used.append(rule.name)
    return exposed.union(residual), tuple(used)


def service_exposures(ctx) -> list[ServiceExposure]:
    cached = ctx.artifacts.get("_service_exposures")
    if cached is not None:
        return cached
    services = protocol_services(ctx)
    out: list[ServiceExposure] = []
    for itf in ctx.resolver.interfaces():
        if itf.lower("status", "up") == "down":
            continue
        access = {v.lower() for v in itf.get_list("allowaccess")}
        wanted = [p for p in ADMIN_PROTOCOLS + AUX_PROTOCOLS if p in access]
        if not wanted:
            continue
        vdom = ctx.resolver.interface_vdom(itf.name) or itf.vdom
        wan, conf = ctx.resolver.interface_is_internet_facing(itf.name)
        for proto in wanted:
            sources, rules = reachable_sources(ctx, vdom, itf.name, services.get(proto))
            out.append(ServiceExposure(itf.name, vdom, proto, wan, conf, sources, rules))
    ctx.artifacts["_service_exposures"] = out
    return out


def sslvpn_state(ctx) -> Optional[dict]:
    for settings in ctx.model.all_singletons("vpn ssl settings"):
        status = settings.lower("status")
        if status == "disable":
            continue
        src_intf = [v.strip('"') for v in settings.get_list("source-interface")]
        enabled = status == "enable" or bool(src_intf)
        if not enabled:
            continue
        wan_intf = [i for i in src_intf
                    if ctx.resolver.interface_is_internet_facing(i)[0] or ctx.is_wan_name(i)]
        sources = settings.get_list("source-address")
        restricted = bool(sources) and not any(s.lower() == "all" for s in sources)
        return {
            "settings": settings,
            "interfaces": src_intf,
            "wan": bool(wan_intf) or not src_intf,
            "wan_interfaces": wan_intf,
            "restricted": restricted,
        }
    return None
