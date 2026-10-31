from __future__ import annotations

from collections import defaultdict

from ..findings import Category, Confidence, Finding
from ..knowledge import BUILTIN_PROFILES, DEFAULT_SSL_CA_NAMES, THREAT_CATEGORIES
from ..models import ConfigObject
from .base import Analyzer, AnalyzerContext, join_names, register

PROFILE_DEFS = [
    ("ips sensor", "ips-sensor"),
    ("antivirus profile", "av-profile"),
    ("webfilter profile", "webfilter-profile"),
    ("dnsfilter profile", "dnsfilter-profile"),
    ("application list", "application-list"),
    ("dlp sensor", "dlp-sensor"),
    ("dlp profile", "dlp-profile"),
    ("file-filter profile", "file-filter-profile"),
    ("emailfilter profile", "emailfilter-profile"),
    ("videofilter profile", "videofilter-profile"),
    ("casb profile", "casb-profile"),
    ("firewall ssl-ssh-profile", "ssl-ssh-profile"),
]
REFERENCE_SECTIONS = ("firewall policy", "firewall policy6", "firewall proxy-policy",
                      "firewall security-policy", "firewall interface-policy",
                      "firewall interface-policy6", "firewall sniffer",
                      "firewall profile-group")
AV_PROTOCOLS = ("http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "ssh", "cifs")
CERT_CHECKS = ("untrusted-server-cert", "expired-server-cert", "revoked-server-cert",
               "cert-validation-failure")
_READABLE = {
    "ips sensor": "IPS sensor", "antivirus profile": "Antivirus profile",
    "webfilter profile": "Web filter profile", "dnsfilter profile": "DNS filter profile",
    "application list": "Application control list", "dlp sensor": "DLP sensor",
    "dlp profile": "DLP profile", "file-filter profile": "File filter profile",
    "emailfilter profile": "Email filter profile", "videofilter profile": "Video filter profile",
    "casb profile": "CASB profile", "firewall ssl-ssh-profile": "SSL/SSH inspection profile",
}


@register
class ProfileAnalyzer(Analyzer):
    name = "profiles"
    category = Category.SECURITY_PROFILE

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        referenced = self._references(ctx)
        findings: list[Finding] = []
        findings.extend(self._unused(ctx, referenced))
        findings.extend(self._ips_monitor_only(ctx, referenced))
        findings.extend(self._av_no_block(ctx, referenced))
        findings.extend(self._ssl_profiles(ctx, referenced))
        findings.extend(self._threat_categories(ctx, referenced))
        return findings

    @staticmethod
    def _references(ctx: AnalyzerContext) -> dict[str, set[str]]:
        referenced: dict[str, set[str]] = defaultdict(set)
        for section in REFERENCE_SECTIONS:
            for obj in ctx.model.objects(section, vdom=None):
                if section != "firewall profile-group" and obj.lower("status", "enable") == "disable":
                    continue
                for _sec, key in PROFILE_DEFS:
                    val = obj.get(key)
                    if val:
                        referenced[key].add(val.strip('"'))
        return referenced

    def _unused(self, ctx: AnalyzerContext, referenced: dict[str, set[str]]) -> list[Finding]:
        out: list[Finding] = []
        for section, key in PROFILE_DEFS:
            for obj in ctx.model.objects(section, vdom=None):
                if not obj.name or obj.name in BUILTIN_PROFILES:
                    continue
                if obj.name in referenced.get(key, set()):
                    continue
                out.append(ctx.finding(
                    "PROFILE_UNUSED", vdom=obj.vdom, affected_object=obj.name,
                    description=(f"{_READABLE[section]} '{obj.name}' isn't used by any "
                                 f"enabled rule or profile group."),
                    evidence=[obj.evidence_line()],
                    confidence=Confidence.MEDIUM))
        return out

    def _ips_monitor_only(self, ctx: AnalyzerContext,
                          referenced: dict[str, set[str]]) -> list[Finding]:
        out: list[Finding] = []
        used = referenced.get("ips-sensor", set())
        for sensor in ctx.model.objects("ips sensor", vdom=None):
            if not sensor.name or sensor.name not in used:
                continue
            actions = [e.lower("action") for e in sensor.child("entries")]
            explicit = [a for a in actions if a]
            if explicit and all(a in ("monitor", "pass") for a in explicit):
                out.append(ctx.finding(
                    "PROFILE_IPS_MONITOR_ONLY", vdom=sensor.vdom, affected_object=sensor.name,
                    description=(f"IPS sensor '{sensor.name}' is used by rules, but every "
                                 f"signature action in it is monitor or pass. Nothing gets "
                                 f"blocked."),
                    evidence=[sensor.evidence_line()],
                    confidence=Confidence.MEDIUM))
        return out

    def _av_no_block(self, ctx: AnalyzerContext,
                     referenced: dict[str, set[str]]) -> list[Finding]:
        out: list[Finding] = []
        used = referenced.get("av-profile", set())
        for prof in ctx.model.objects("antivirus profile", vdom=None):
            if not prof.name or prof.name not in used:
                continue
            monitor, block = [], []
            for proto in AV_PROTOCOLS:
                child = prof.child_singleton(proto)
                if child is None:
                    continue
                mode = child.lower("av-scan")
                options = {v.lower() for v in child.get_list("options")}
                if mode == "monitor" or "avmonitor" in options:
                    monitor.append(proto)
                elif mode == "block" or "scan" in options:
                    block.append(proto)
            if monitor and not block:
                out.append(ctx.finding(
                    "PROFILE_AV_NO_BLOCK", vdom=prof.vdom, affected_object=prof.name,
                    description=(f"Antivirus profile '{prof.name}' only monitors "
                                 f"{', '.join(monitor).upper()}. Malware it finds is logged "
                                 f"and delivered anyway."),
                    evidence=[prof.evidence_line()],
                    confidence=Confidence.MEDIUM))
        return out

    def _ssl_profiles(self, ctx: AnalyzerContext,
                      referenced: dict[str, set[str]]) -> list[Finding]:
        out: list[Finding] = []
        used = referenced.get("ssl-ssh-profile", set())
        for prof in ctx.model.objects("firewall ssl-ssh-profile", vdom=None):
            if not prof.name or prof.name not in used:
                continue
            if ctx.resolver.ssl_depth(prof.vdom, prof.name) != "deep":
                continue
            ca = (prof.get("caname") or "Fortinet_CA_SSL").strip('"')
            if ca.lower() in DEFAULT_SSL_CA_NAMES:
                out.append(ctx.finding(
                    "PROFILE_SSL_DEFAULT_CA", vdom=prof.vdom, affected_object=prof.name,
                    description=(f"SSL/SSH profile '{prof.name}' does deep inspection and "
                                 f"signs with the factory CA '{ca}'."),
                    evidence=[prof.evidence_line(), f"caname {ca}"
                              + ("" if prof.get("caname") else " (the default)")],
                    confidence=Confidence.HIGH if prof.get("caname") else Confidence.MEDIUM))
            ignored = self._ignored_checks(prof)
            if ignored:
                out.append(ctx.finding(
                    "PROFILE_SSL_CERT_CHECKS_IGNORED", vdom=prof.vdom, affected_object=prof.name,
                    description=(f"SSL/SSH profile '{prof.name}' re-signs server certificates "
                                 f"that fail validation instead of warning users "
                                 f"({join_names(ignored)})."),
                    evidence=[prof.evidence_line()] + [f"set {c} ignore" for c in ignored],
                    confidence=Confidence.HIGH))
        return out

    @staticmethod
    def _ignored_checks(prof: ConfigObject) -> list[str]:
        blocks = [prof] + [c for key in ("ssl", "https", "ssl-server") for c in prof.child(key)]
        found = []
        for block in blocks:
            for check in CERT_CHECKS:
                if block.lower(check) == "ignore":
                    label = check if block is prof else f"{check} in {block.section}"
                    if label not in found:
                        found.append(label)
        return found

    def _threat_categories(self, ctx: AnalyzerContext,
                           referenced: dict[str, set[str]]) -> list[Finding]:
        out: list[Finding] = []
        for section, key, block in (("webfilter profile", "webfilter-profile", "ftgd-wf"),
                                    ("dnsfilter profile", "dnsfilter-profile", "ftgd-dns")):
            used = referenced.get(key, set())
            for prof in ctx.model.objects(section, vdom=None):
                if not prof.name or prof.name not in used:
                    continue
                container = prof.child_singleton(block)
                filters = container.child("filters") if container else []
                blocked = {f.get("category") for f in filters if f.lower("action") == "block"}
                missing = [f"{name} ({cid})" for cid, name in THREAT_CATEGORIES.items()
                           if str(cid) not in blocked]
                if not missing:
                    continue
                how = ("has no FortiGuard category filtering at all" if not filters
                       else f"doesn't block {join_names(missing)}")
                out.append(ctx.finding(
                    "PROFILE_THREAT_CATEGORIES_ALLOWED", vdom=prof.vdom,
                    affected_object=prof.name,
                    description=f"{_READABLE[section]} '{prof.name}' is in use and {how}.",
                    evidence=[prof.evidence_line()],
                    confidence=Confidence.MEDIUM))
        return out
