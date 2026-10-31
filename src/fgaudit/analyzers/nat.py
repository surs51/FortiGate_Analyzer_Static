from __future__ import annotations

from ..findings import Category, Confidence, Exposure, Finding
from ..object_resolver.algebra import ipset_to_strings
from .base import Analyzer, AnalyzerContext, join_names, register

_RAW_IP_MAX_HOSTS = 256


@register
class NatAnalyzer(Analyzer):
    name = "nat"
    category = Category.FIREWALL_POLICY

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        modes: dict[str, str] = ctx.artifacts.setdefault("nat_mode", {})
        for vdom in ctx.model.policy_vdoms:
            central = ctx.resolver.central_nat(vdom)
            modes[vdom] = "central-nat" if central else "policy-nat"
            if central:
                findings.extend(self._central_internal_snat(ctx, vdom))
            else:
                findings.extend(self._vip_raw_ip_misuse(ctx, vdom))
                findings.extend(self._internal_snat(ctx, vdom))
        return findings

    def _vip_raw_ip_misuse(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        vips = [v for v in ctx.sets.vips(vdom).values() if v.enabled and not v.mapped.is_empty()]
        if not vips:
            return out
        for ep in ctx.effective(vdom):
            if not ep.enabled or not ep.is_allow or ep.targets_vip:
                continue
            if not ctx.is_wan_intf_set(ep.src_intf):
                continue
            dst = ep.dst_ip
            if not dst.is_determinate() or dst.is_empty() or dst.is_broad():
                continue
            if dst.v4_count() > _RAW_IP_MAX_HOSTS:
                continue
            clashes = [v for v in vips if dst.overlaps(v.mapped)]
            if not clashes:
                continue
            names = join_names(sorted(v.name for v in clashes), 4)
            first = clashes[0]
            out.append(ctx.finding(
                "NAT_VIP_RAW_IP", vdom=vdom, affected_object=ep.label,
                description=(f"{ep.label} comes from the internet side and its destination "
                             f"({', '.join(ipset_to_strings(dst, 4))}) is the internal "
                             f"address behind VIP {names}. In policy NAT mode inbound rules "
                             f"have to use the VIP itself, so this rule either never matches "
                             f"the published traffic or opens a path around the VIP."),
                evidence=[ep.policy.evidence_line(), first.obj.evidence_line(),
                          f"VIP {first.name}: {first.external_label()} -> {first.mapped_label()}"],
                confidence=Confidence.MEDIUM,
                exposure=Exposure.INTERNET_FACING))
        return out

    def _internal_snat(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        for ep in ctx.effective(vdom):
            pol = ep.policy
            if not ep.enabled or not ep.is_allow or not ep.nat:
                continue
            if ep.src_intf.is_any or ep.dst_intf.is_any:
                continue
            if ctx.is_wan_intf_set(ep.src_intf) or ctx.is_wan_intf_set(ep.dst_intf):
                continue
            dst_roles = ctx.resolver.interface_roles(vdom, pol.get_list("dstintf"))
            if dst_roles & {"vpn", "remote"}:
                continue
            out.append(ctx.finding(
                "NAT_INTERNAL_SNAT", vdom=vdom, affected_object=ep.label,
                description=(f"{ep.label} translates the source address for traffic from "
                             f"{', '.join(ep.src_intf.to_strings())} to "
                             f"{', '.join(ep.dst_intf.to_strings())}. Servers on the "
                             f"destination side will log the firewall instead of the real "
                             f"client."),
                evidence=[pol.evidence_line(), "set nat enable"],
                confidence=Confidence.LOW,
                exposure=Exposure.INTERNAL))
        return out

    def _central_internal_snat(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        for entry in ctx.model.local_objects("firewall central-snat-map", vdom):
            if entry.lower("status", "enable") == "disable" or not entry.flag("nat", True):
                continue
            src = ctx.sets.resolve_intf(vdom, entry.get_list("srcintf"))
            dst = ctx.sets.resolve_intf(vdom, entry.get_list("dstintf"))
            if src.is_any or dst.is_any or not src.names or not dst.names:
                continue
            if ctx.is_wan_intf_set(src) or ctx.is_wan_intf_set(dst):
                continue
            label = f"central SNAT entry {entry.name}"
            out.append(ctx.finding(
                "NAT_INTERNAL_SNAT", vdom=vdom, affected_object=label,
                description=(f"{label} translates the source address for traffic from "
                             f"{', '.join(src.to_strings())} to {', '.join(dst.to_strings())}. "
                             f"Servers on the destination side will log the firewall instead "
                             f"of the real client."),
                evidence=[entry.evidence_line()],
                confidence=Confidence.LOW,
                exposure=Exposure.INTERNAL))
        return out
