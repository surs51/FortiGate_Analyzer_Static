from __future__ import annotations

import ipaddress
from typing import Optional

from ..object_resolver import EffectivePolicy, SetResolver, VipInfo
from ..object_resolver.algebra import IPSet, ServiceSet
from ..parser import parse_config

_USAGE = ("Couldn't read the lookup. Use: srcintf,srcip,dstintf,dstip,proto,port "
          "(for example wan1,203.0.113.9,dmz,10.0.0.50,tcp,443). proto is tcp, udp, sctp "
          "or icmp; for icmp, port is the ICMP type.")

YES, NO, MAYBE = "yes", "no", "maybe"


def _ip_state(ipset: IPSet, value: int, version: int) -> str:
    intervals = ipset.v4 if version == 4 else ipset.v6
    if intervals.covers(value):
        return MAYBE if ipset.inexact else YES
    if ipset.opaque:
        return MAYBE
    return NO


def _service_state(svc: ServiceSet, proto: str, port: int) -> str:
    if svc.carries(proto, port):
        return MAYBE if svc.inexact else YES
    if svc.opaque:
        return MAYBE
    return NO


def _vip_for(vips: dict[str, VipInfo], sets: SetResolver, vdom: str, srcintf: str,
             dip: int, version: int, proto: str, port: int) -> Optional[VipInfo]:
    for vip in vips.values():
        if not vip.enabled or _ip_state(vip.external, dip, version) != YES:
            continue
        if vip.extintf != "any":
            listen = sets.zone_members(vdom, vip.extintf) or [vip.extintf]
            if srcintf not in listen:
                continue
        if vip.portforward and (vip.protocol != proto or not vip.ext_ports.covers(port)):
            continue
        return vip
    return None


def _mapped_port(vip: VipInfo, port: int) -> int:
    if not vip.portforward or not vip.mapped_ports or not vip.ext_ports.intervals:
        return port
    offset = port - vip.ext_ports.intervals[0][0]
    return vip.mapped_ports.intervals[0][0] + offset


def run_lookup(text: str, spec: str) -> str:
    try:
        srcintf, srcip, dstintf, dstip, proto, port = [s.strip() for s in spec.split(",")]
        sip_obj = ipaddress.ip_address(srcip)
        dip_obj = ipaddress.ip_address(dstip)
        pnum = int(port)
        proto = proto.lower()
        if proto not in ("tcp", "udp", "sctp", "icmp"):
            raise ValueError(proto)
    except (ValueError, IndexError):
        return _USAGE
    version = sip_obj.version
    sip, dip = int(sip_obj), int(dip_obj)

    model = parse_config(text)
    sets = SetResolver(model)
    packet = f"{proto}/{port} from {srcip} on {srcintf} to {dstip} on {dstintf}"

    for vdom in model.policy_vdoms:
        policies = sets.effective_policies(vdom)
        if not policies:
            continue
        vip = _vip_for(sets.vips(vdom), sets, vdom, srcintf, dip, version, proto, pnum)
        check_port = _mapped_port(vip, pnum) if vip else pnum
        maybes: list[tuple[EffectivePolicy, str]] = []
        for ep in policies:
            if not ep.enabled:
                continue
            if not ep.src_intf.contains(srcintf) or not ep.dst_intf.contains(dstintf):
                continue
            if vip is not None:
                if ep.targets_vip:
                    if vip.name not in {v.name for v in ep.vips}:
                        continue
                elif not (ep.action == "deny" and ep.match_vip):
                    continue
            elif ep.targets_vip:
                continue
            dst_state = YES if (vip is not None and ep.targets_vip) else _ip_state(ep.dst_ip, dip, version)
            states = (_ip_state(ep.src_ip, sip, version), dst_state,
                      _service_state(ep.service, proto, check_port))
            if NO in states:
                continue
            reasons = []
            if MAYBE in states:
                reasons.append("it uses FQDN, geography, internet-service or similar objects "
                               "that can't be resolved offline")
            if ep.identity:
                reasons.append("it only applies to authenticated users")
            if ep.schedule not in ("always", ""):
                reasons.append(f"it only applies during schedule '{ep.schedule}'")
            if reasons:
                maybes.append((ep, " and ".join(reasons)))
                continue
            return _describe_hit(vdom, ep, packet, vip, check_port, maybes)
        lines = [f"VDOM {vdom}: no rule matches {packet}, so it hits the implicit deny at "
                 f"the bottom of the table and is dropped."]
        if vip:
            lines.append(f"The destination is the external address of VIP {vip.name}, so only "
                         f"rules that use that VIP (and deny rules with match-vip) were considered.")
        lines.extend(_maybe_lines(maybes))
        return "\n".join(lines)
    return f"No rules found. {packet} would hit the implicit deny and be dropped."


def _maybe_lines(maybes: list[tuple[EffectivePolicy, str]]) -> list[str]:
    if not maybes:
        return []
    out = ["These rules come earlier and might match instead:"]
    out.extend(f"  - {ep.label} ({ep.action}), because {why}" for ep, why in maybes[:10])
    return out


def _describe_hit(vdom: str, ep: EffectivePolicy, packet: str, vip: Optional[VipInfo],
                  check_port: int, maybes: list[tuple[EffectivePolicy, str]]) -> str:
    verdict = "accepted" if ep.is_allow else "dropped"
    lines = [f"VDOM {vdom}: {packet} matches {ep.label} and is {verdict}.",
             "It's the first rule from the top whose interfaces, addresses and service all "
             "include this packet."]
    if vip is not None:
        lines.append(f"The destination is VIP {vip.name}, which forwards it to "
                     f"{vip.mapped_label()}. The rule's service was checked against port "
                     f"{check_port}, the port after translation.")
    if ep.is_allow:
        profiles = ep.profile_map()
        shown = ", ".join(f"{k} {v}" for k, v in sorted(profiles.items())) or "none"
        lines.append(f"Security profiles on this rule: {shown}.")
    lines.extend(_maybe_lines(maybes))
    return "\n".join(lines)
