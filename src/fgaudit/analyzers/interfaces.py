from __future__ import annotations

from collections import defaultdict

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..models import ConfigObject
from .access import ADMIN_PROTOCOLS, AUX_PROTOCOLS, ServiceExposure, service_exposures
from .base import Analyzer, AnalyzerContext, and_join, join_names, plural, register

ROLE_EXEMPT_TYPES = {"loopback", "tunnel", "vap-switch", "vdom-link", "wl-mesh", "ssl",
                     "switch-vlan", "fext-wan"}
_CONF = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


def _describe(protos: list[str]) -> str:
    return and_join(p.upper() if p in ("https", "http", "ssh", "snmp") else p for p in protos)


@register
class InterfaceAnalyzer(Analyzer):
    name = "interface"
    category = Category.INTERFACE

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._internet_listeners(ctx))
        for itf in ctx.resolver.interfaces():
            findings.extend(self._unneeded(ctx, itf))
            findings.extend(self._loopback(ctx, itf))
            findings.extend(self._antispoof(ctx, itf))
        findings.extend(self._missing_roles(ctx))
        findings.extend(self._sdwan(ctx))
        return findings

    def _internet_listeners(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        by_iface: dict[str, list[ServiceExposure]] = defaultdict(list)
        for exp in service_exposures(ctx):
            if exp.wan:
                by_iface[exp.interface].append(exp)

        for iface, exposures in by_iface.items():
            reason = ctx.resolver.wan_reason(iface)
            confidence = _CONF.get(exposures[0].wan_confidence, Confidence.LOW)
            itf = ctx.resolver.interface(iface)
            ev = [itf.evidence_line() if itf else f"interface {iface}",
                  f"allowaccess {' '.join(itf.get_list('allowaccess')) if itf else '?'}"]
            for rule_id, group in (("IFACE_MGMT_ON_WAN", ADMIN_PROTOCOLS),
                                   ("IFACE_AUX_SERVICE_ON_WAN", AUX_PROTOCOLS)):
                reachable = [e for e in exposures if e.protocol in group and not e.unreachable]
                if not reachable:
                    continue
                open_all = [e for e in reachable if e.unrestricted]
                limited = [e for e in reachable if not e.unrestricted]
                rules = sorted({r for e in reachable for r in e.local_in_rules})
                extra = [f"local-in policies considered: {', '.join(rules)}"] if rules else []
                what = "management" if rule_id == "IFACE_MGMT_ON_WAN" else "service"
                if open_all:
                    desc = (f"Interface {iface} faces the internet (it {reason}) and accepts "
                            f"{_describe([e.protocol for e in open_all])} {what} connections "
                            f"from any address.")
                    if limited:
                        desc += (f" {_describe([e.protocol for e in limited])} "
                                 f"{'is' if len(limited) == 1 else 'are'} limited by local-in "
                                 f"policy to {limited[0].sources_text()}.")
                    severity = None
                else:
                    desc = (f"Interface {iface} faces the internet (it {reason}) and accepts "
                            f"{_describe([e.protocol for e in limited])} {what} connections. "
                            f"A local-in policy limits them to {limited[0].sources_text()}, "
                            f"which helps, but the listener is still there for those sources.")
                    severity = Severity.MEDIUM if rule_id == "IFACE_MGMT_ON_WAN" else Severity.LOW
                out.append(ctx.finding(
                    rule_id, vdom=exposures[0].vdom, affected_object=iface,
                    description=desc, evidence=ev + extra, severity=severity,
                    confidence=confidence, exposure=Exposure.MANAGEMENT_PLANE))
        return out

    def _unneeded(self, ctx: AnalyzerContext, itf: ConfigObject) -> list[Finding]:
        access = {v.lower() for v in itf.get_list("allowaccess")}
        if not access or ctx.resolver.interface_is_internet_facing(itf.name)[0]:
            return []
        unused: list[str] = []
        if "snmp" in access and not _snmp_agent_enabled(ctx):
            unused.append("snmp (the SNMP agent is off)")
        if "fgfm" in access and not _fortimanager_configured(ctx):
            unused.append("fgfm (no FortiManager is configured)")
        if "fabric" in access and not _fabric_enabled(ctx):
            unused.append("fabric (Security Fabric is off)")
        if not unused:
            return []
        return [ctx.finding(
            "IFACE_UNNEEDED_PROTOCOL",
            vdom=ctx.resolver.interface_vdom(itf.name) or itf.vdom,
            affected_object=itf.name,
            description=f"Interface {itf.name} allows {', '.join(unused)}.",
            evidence=[itf.evidence_line(), f"allowaccess {' '.join(itf.get_list('allowaccess'))}"],
            confidence=Confidence.HIGH)]

    def _loopback(self, ctx: AnalyzerContext, itf: ConfigObject) -> list[Finding]:
        if itf.lower("type") != "loopback":
            return []
        access = [p for p in itf.get_list("allowaccess") if p.lower() in ADMIN_PROTOCOLS]
        if not access:
            return []
        vdom = ctx.resolver.interface_vdom(itf.name) or itf.vdom
        from_internet = [ep for ep in ctx.effective(vdom)
                         if ep.enabled and ep.is_allow and ep.dst_intf.contains(itf.name)
                         and ctx.is_wan_intf_set(ep.src_intf)]
        if from_internet:
            desc = (f"Loopback {itf.name} accepts {_describe(access)} management, and "
                    f"{join_names([ep.label for ep in from_internet], 4)} lets internet "
                    f"traffic reach it.")
            severity, exposure = Severity.HIGH, Exposure.MANAGEMENT_PLANE
        else:
            desc = (f"Loopback {itf.name} accepts {_describe(access)} management. No rule "
                    f"from the internet side reaches it right now.")
            severity, exposure = None, Exposure.INTERNAL
        return [ctx.finding(
            "IFACE_EXPOSED_LOOPBACK", vdom=vdom, affected_object=itf.name,
            description=desc, evidence=[itf.evidence_line()],
            severity=severity, confidence=Confidence.MEDIUM, exposure=exposure)]

    def _antispoof(self, ctx: AnalyzerContext, itf: ConfigObject) -> list[Finding]:
        if itf.lower("src-check", "enable") != "disable":
            return []
        wan = ctx.resolver.interface_is_internet_facing(itf.name)[0]
        return [ctx.finding(
            "IFACE_NO_ANTISPOOF",
            vdom=ctx.resolver.interface_vdom(itf.name) or itf.vdom,
            affected_object=itf.name,
            description=(f"Reverse-path checking is disabled on {itf.name}"
                         + (", which faces the internet." if wan else ".")),
            evidence=[itf.evidence_line(), "set src-check disable"],
            severity=None if wan else Severity.LOW,
            confidence=Confidence.HIGH,
            exposure=Exposure.INTERNET_FACING if wan else Exposure.INTERNAL)]

    def _missing_roles(self, ctx: AnalyzerContext) -> list[Finding]:
        by_vdom: dict[str, list[ConfigObject]] = defaultdict(list)
        for itf in ctx.resolver.interfaces():
            if itf.lower("role", "undefined") not in ("", "undefined"):
                continue
            if itf.lower("type") in ROLE_EXEMPT_TYPES or itf.lower("status", "up") == "down":
                continue
            ip = itf.get("ip") or ""
            addressed = (ip and not ip.startswith("0.0.0.0")) or itf.lower("mode") in ("dhcp", "pppoe")
            if not addressed:
                continue
            by_vdom[ctx.resolver.interface_vdom(itf.name) or itf.vdom].append(itf)
        out = []
        for vdom, items in by_vdom.items():
            names = sorted(i.name for i in items)
            out.append(ctx.finding(
                "IFACE_MISSING_ROLE", vdom=vdom, affected_object=join_names(names, 8),
                description=(f"{plural(len(names), 'interface')} with an address "
                             f"{'has' if len(names) == 1 else 'have'} no role: "
                             f"{join_names(names, 20)}."),
                evidence=[i.evidence_line() for i in items[:8]],
                confidence=Confidence.LOW))
        return out

    def _sdwan(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        for section in ("system sdwan", "system virtual-wan-link"):
            for sdwan in ctx.model.all_singletons(section):
                if sdwan.lower("status", "disable") != "enable":
                    continue
                members = sdwan.child("members")
                if members and not sdwan.child("health-check"):
                    out.append(ctx.finding(
                        "IFACE_INSECURE_SDWAN", vdom=sdwan.vdom, affected_object=section,
                        description=(f"SD-WAN is on with {plural(len(members), 'member link')} "
                                     f"but no health check."),
                        evidence=[sdwan.evidence_line()],
                        confidence=Confidence.HIGH))
        return out


def _snmp_agent_enabled(ctx: AnalyzerContext) -> bool:
    sysinfo = ctx.model.first("system snmp sysinfo")
    return bool(sysinfo) and sysinfo.lower("status", "disable") == "enable"


def _fortimanager_configured(ctx: AnalyzerContext) -> bool:
    cm = ctx.model.first("system central-management")
    return bool(cm) and (cm.get("fmg") or "0.0.0.0") not in ("", "0.0.0.0")


def _fabric_enabled(ctx: AnalyzerContext) -> bool:
    csf = ctx.model.first("system csf")
    return bool(csf) and csf.lower("status", "disable") == "enable"
