from __future__ import annotations

from ..findings import Category, Confidence, Finding, Severity
from ..models import ROOT_VDOM, ConfigObject
from .base import Analyzer, AnalyzerContext, register


def _heartbeat_interfaces(ha: ConfigObject) -> list[str]:
    return [t.strip().strip('"') for t in ha.get_list("hbdev")
            if t.strip().strip('"') and not t.strip().isdigit()]


def _session_sync_cluster(ctx: AnalyzerContext) -> bool:
    fgsp = ctx.model.first("system standalone-cluster")
    has_peers = fgsp is not None and bool(fgsp.get_list("cluster-peer") or fgsp.child("cluster-peer"))
    return has_peers or bool(ctx.model.objects("system cluster-sync", vdom=None))


@register
class HaAnalyzer(Analyzer):
    name = "high_availability"
    category = Category.HIGH_AVAILABILITY

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        ha = ctx.model.first("system ha")
        mode = ha.lower("mode", "standalone") if ha else "standalone"
        vdom = ha.vdom if ha else ROOT_VDOM

        if mode == "standalone":
            if _session_sync_cluster(ctx):
                return []
            return [ctx.finding(
                "HA_STANDALONE", vdom=vdom, affected_object="system ha",
                description="This firewall runs on its own, without an HA partner.",
                evidence=[ha.evidence_line() if ha else "config system ha is at its defaults"],
                confidence=Confidence.LOW)]

        findings: list[Finding] = []
        if ha.lower("session-pickup", "disable") != "enable":
            findings.append(ctx.finding(
                "HA_NO_SESSION_SYNC", vdom=vdom, affected_object="system ha",
                description=f"The {mode} cluster doesn't synchronise sessions.",
                evidence=[ha.evidence_line(), "session-pickup is not enabled"],
                confidence=Confidence.MEDIUM))

        hb = _heartbeat_interfaces(ha)
        if len(hb) <= 1:
            if hb:
                desc = f"The cluster has only one heartbeat interface ({hb[0]})."
            else:
                desc = "The cluster has no heartbeat interface set."
            findings.append(ctx.finding(
                "HA_SPLIT_BRAIN_RISK", vdom=vdom, affected_object="system ha",
                description=desc,
                evidence=[ha.evidence_line(),
                          f"hbdev {' '.join(ha.get_list('hbdev')) or '(not set)'}"],
                confidence=Confidence.MEDIUM))

        has_password = bool(ha.get("password"))
        problems = []
        if not has_password:
            problems.append("there's no group password")
        if ha.lower("authentication", "disable") != "enable":
            problems.append("heartbeat authentication is off")
        if ha.lower("encryption", "disable") != "enable":
            problems.append("heartbeat encryption is off")
        if problems:
            findings.append(ctx.finding(
                "HA_WEAK_AUTH", vdom=vdom, affected_object="system ha",
                description="The HA heartbeat isn't fully protected: " + ", ".join(problems) + ".",
                evidence=[ha.evidence_line()],
                severity=None if not has_password else Severity.LOW,
                confidence=Confidence.HIGH))
        return findings
