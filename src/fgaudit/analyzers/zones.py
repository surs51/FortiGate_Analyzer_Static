from __future__ import annotations

from ..findings import Category, Confidence, Exposure, Finding
from .base import Analyzer, AnalyzerContext, register


@register
class ZoneAnalyzer(Analyzer):
    name = "zones"
    category = Category.INTERFACE

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        version = ctx.version
        old_default_allow = version is not None and not version.at_least(5, 2)
        for zone in ctx.model.objects("system zone", vdom=None):
            if not zone.name:
                continue
            members = zone.get_list("interface")
            if len(members) <= 1:
                continue
            setting = zone.lower("intrazone")
            if setting == "allow":
                findings.append(ctx.finding(
                    "ZONE_INTRAZONE_ALLOW",
                    vdom=zone.vdom,
                    affected_object=zone.name,
                    description=(
                        f"Zone '{zone.name}' has intrazone set to allow, so traffic between "
                        f"its {len(members)} interfaces ({', '.join(members)}) passes without "
                        f"any rule. The policy table won't show it."),
                    evidence=[zone.evidence_line(), "set intrazone allow",
                              f"members: {', '.join(members)}"],
                    confidence=Confidence.HIGH,
                    exposure=Exposure.INTERNAL,
                ))
            elif not setting and old_default_allow:
                findings.append(ctx.finding(
                    "ZONE_INTRAZONE_IMPLICIT",
                    vdom=zone.vdom,
                    affected_object=zone.name,
                    description=(
                        f"Zone '{zone.name}' has {len(members)} interfaces and doesn't set "
                        f"intrazone. FortiOS {version} allowed intra-zone traffic by default, "
                        f"so these interfaces may talk to each other without a rule."),
                    evidence=[zone.evidence_line(), f"members: {', '.join(members)}"],
                    confidence=Confidence.MEDIUM,
                    exposure=Exposure.INTERNAL,
                ))
        return findings
