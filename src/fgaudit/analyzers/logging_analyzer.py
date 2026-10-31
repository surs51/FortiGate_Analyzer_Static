from __future__ import annotations

from typing import Optional

from ..findings import Category, Confidence, Finding
from ..models import ROOT_VDOM, ConfigObject
from .base import Analyzer, AnalyzerContext, join_names, register

FAZ_SECTIONS = ("log fortianalyzer setting", "log fortianalyzer2 setting",
                "log fortianalyzer3 setting", "log fortianalyzer-cloud setting")
CLOUD_SECTIONS = ("log fortiguard setting",)
SYSLOG_SECTIONS = ("log syslogd setting", "log syslogd2 setting",
                   "log syslogd3 setting", "log syslogd4 setting")
DEFAULT_DISK_LOG_AGE = 7


def _enabled(obj: Optional[ConfigObject]) -> bool:
    return obj is not None and obj.lower("status", "disable") == "enable"


def _first(ctx: AnalyzerContext, section: str) -> Optional[ConfigObject]:
    return ctx.model.first(section)


@register
class LoggingAnalyzer(Analyzer):
    name = "logging"
    category = Category.LOGGING

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        remote = {s: _first(ctx, s) for s in FAZ_SECTIONS + CLOUD_SECTIONS + SYSLOG_SECTIONS}
        active = [s for s, obj in remote.items() if _enabled(obj)]
        present = [obj for obj in remote.values() if obj is not None]
        rep_vdom = present[0].vdom if present else ROOT_VDOM

        if not active:
            findings.append(ctx.finding(
                "LOG_NO_FORTIANALYZER", vdom=rep_vdom, affected_object="remote logging",
                description=("No remote log destination is enabled: no FortiAnalyzer, no "
                             "FortiCloud logging and no syslog server. Logs exist only on the "
                             "firewall itself."),
                evidence=[obj.evidence_line() for obj in present][:4]
                or ["no log fortianalyzer or log syslogd settings are enabled"],
                confidence=Confidence.HIGH))

        findings.extend(self._syslog_transport(ctx, remote))
        findings.extend(self._retention(ctx, bool(active)))
        findings.extend(self._event_logging(ctx))
        return findings

    def _syslog_transport(self, ctx: AnalyzerContext,
                          remote: dict[str, Optional[ConfigObject]]) -> list[Finding]:
        plain = []
        for section in SYSLOG_SECTIONS:
            obj = remote.get(section)
            if not _enabled(obj):
                continue
            mode = obj.lower("mode", "udp")
            enc = obj.lower("enc-algorithm", "disable")
            if mode != "reliable" or enc == "disable":
                plain.append((section, obj, mode))
        if not plain:
            return []
        names = [f"{s.replace('log ', '').replace(' setting', '')} ({o.get('server') or '?'}, "
                 f"{'UDP' if m == 'udp' else 'TCP without TLS'})" for s, o, m in plain]
        return [ctx.finding(
            "LOG_TRANSPORT_INSECURE", vdom=plain[0][1].vdom,
            affected_object=join_names([p[0] for p in plain]),
            description=f"Logs go to {join_names(names)} without encryption.",
            evidence=[o.evidence_line() for _, o, _ in plain],
            confidence=Confidence.HIGH)]

    def _retention(self, ctx: AnalyzerContext, has_remote: bool) -> list[Finding]:
        disk = _first(ctx, "log disk setting")
        if disk is None or has_remote:
            return []
        if disk.lower("status", "enable") != "enable":
            return []
        raw = disk.get("maximum-log-age")
        try:
            age = int(raw) if raw is not None else DEFAULT_DISK_LOG_AGE
        except ValueError:
            return []
        if age == 0 or age >= ctx.config.short_retention_days:
            return []
        how = "" if raw is not None else " (the FortiOS default, since it isn't set)"
        return [ctx.finding(
            "LOG_SHORT_RETENTION", vdom=disk.vdom, affected_object="log disk setting",
            description=(f"Local disk logs are deleted after {age} days{how}, and there's no "
                         f"remote copy. The review's minimum is "
                         f"{ctx.config.short_retention_days} days."),
            evidence=[disk.evidence_line(), f"maximum-log-age {age}"],
            confidence=Confidence.HIGH if raw is not None else Confidence.MEDIUM)]

    def _event_logging(self, ctx: AnalyzerContext) -> list[Finding]:
        evt = _first(ctx, "log eventfilter")
        if evt is None or evt.lower("event", "enable") != "disable":
            return []
        return [ctx.finding(
            "LOG_NO_EVENT", vdom=evt.vdom, affected_object="log eventfilter",
            description="Event logging is turned off (log eventfilter / event disable).",
            evidence=[evt.evidence_line(), "set event disable"],
            confidence=Confidence.HIGH)]
