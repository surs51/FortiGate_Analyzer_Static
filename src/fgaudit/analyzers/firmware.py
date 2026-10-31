from __future__ import annotations

from typing import Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..knowledge import KNOWN_VULNS, FosVersion, KnownVuln, is_end_of_support
from ..models import ConfigObject
from .access import service_exposures, sslvpn_state
from .base import Analyzer, AnalyzerContext, join_names, register

_FEATURE_NAMES = {
    "sslvpn": "SSL-VPN",
    "admin": "the HTTP/HTTPS admin interface",
    "fgfm": "FortiManager access (fgfm)",
}


@register
class FirmwareAnalyzer(Analyzer):
    name = "firmware"
    category = Category.HARDENING

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        meta = ctx.meta or {}
        model = meta.get("platform") or "unknown model"
        version_text = meta.get("fortios_version") or "unknown"
        build = meta.get("build") or "?"
        vdom = ctx.model.policy_vdoms[0]
        version = ctx.version

        out: list[Finding] = [ctx.finding(
            "FW_VERSION_REVIEW", vdom=vdom,
            affected_object=f"{model} {version_text} (build {build})",
            description=(f"The backup is from an {model} running FortiOS {version_text} "
                         f"(build {build}). Check it against the current Fortinet PSIRT "
                         f"advisories; this review only knows about issues up to its own "
                         f"release." + ("" if version is None or version.patch is not None
                                        else " The header doesn't include the patch level, "
                                             "so version-specific checks were skipped.")),
            evidence=[meta.get("raw_header") or "no #config-version header found"],
            confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE)]

        if version is not None and is_end_of_support(version, ctx.today):
            out.append(ctx.finding(
                "FW_END_OF_SUPPORT", vdom=vdom, affected_object=f"FortiOS {version}",
                description=(f"FortiOS {version.major}.{version.minor} no longer receives "
                             f"security fixes from Fortinet."),
                evidence=[meta.get("raw_header") or f"FortiOS {version}"],
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))

        if version is not None and version.patch is not None:
            out.extend(self._known_vulns(ctx, version, vdom))

        feed = ctx.psirt_feed
        if feed and model != "unknown model" and version_text != "unknown":
            advisories = (feed.get(model) or {}).get(version_text) or []
            if advisories:
                out.append(ctx.finding(
                    "FW_PSIRT_MATCH", vdom=vdom, affected_object=f"{model} {version_text}",
                    description=(f"Your advisory feed lists {len(advisories)} "
                                 f"{'advisory' if len(advisories) == 1 else 'advisories'} for "
                                 f"{model} {version_text}."),
                    evidence=[str(a) for a in advisories[:20]],
                    confidence=Confidence.MEDIUM, exposure=Exposure.MANAGEMENT_PLANE))
        return out

    def _feature_state(self, ctx: AnalyzerContext, feature: str
                       ) -> tuple[bool, bool, str, list[ConfigObject]]:
        if feature == "sslvpn":
            state = sslvpn_state(ctx)
            if state is None:
                return False, False, "not enabled", []
            where = join_names(state["interfaces"]) or "all interfaces"
            return True, state["wan"], f"enabled on {where}", [state["settings"]]
        protocols = ("https", "http") if feature == "admin" else ("fgfm",)
        what = "HTTP/HTTPS admin access" if feature == "admin" else "fgfm access"
        exposures = [e for e in service_exposures(ctx)
                     if e.protocol in protocols and not e.unreachable]
        if not exposures:
            return False, False, f"no interface allows {what}", []
        on_wan = [e for e in exposures if e.wan and e.unrestricted]
        names = sorted({e.interface for e in (on_wan or exposures)})
        objs = [o for o in (ctx.resolver.interface(n) for n in names) if o is not None]
        return True, bool(on_wan), f"allowed on {join_names(names, 6)}", objs

    def _known_vulns(self, ctx: AnalyzerContext, version: FosVersion, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        for vuln in KNOWN_VULNS:
            if not vuln.affects(version):
                continue
            enabled, internet, detail, objs = self._feature_state(ctx, vuln.feature)
            out.append(self._vuln_finding(ctx, vuln, version, vdom, enabled, internet, detail,
                                          objs))
        return out

    def _vuln_finding(self, ctx: AnalyzerContext, vuln: KnownVuln, version: FosVersion,
                      vdom: str, enabled: bool, internet: bool, detail: str,
                      objs: list[ConfigObject]) -> Finding:
        feature = _FEATURE_NAMES[vuln.feature]
        severity: Optional[Severity]
        if enabled and internet:
            severity, reach = Severity.CRITICAL, " and reachable from the internet"
        elif enabled:
            severity, reach = Severity.HIGH, ", though not from the internet as far as this backup shows"
        else:
            severity, reach = Severity.LOW, None
        exploited = (" It's in CISA's catalog of known exploited vulnerabilities."
                     if vuln.actively_exploited else "")
        if reach:
            desc = (f"FortiOS {version} is affected by {vuln.cve} ({vuln.advisory}): "
                    f"{vuln.summary}. The vulnerable code is in {feature}, which is "
                    f"{detail} here{reach}.{exploited}")
        else:
            desc = (f"FortiOS {version} is affected by {vuln.cve} ({vuln.advisory}): "
                    f"{vuln.summary}. The vulnerable code is in {feature}, which isn't "
                    f"enabled in this backup, so it can't be reached right now. Upgrade "
                    f"anyway: one config change would expose it.")
        return ctx.finding(
            "FW_KNOWN_EXPLOITED", vdom=vdom, affected_object=f"{vuln.cve} on FortiOS {version}",
            description=desc,
            evidence=[f"{vuln.cve} / {vuln.advisory}", f"{feature}: {detail}"]
                     + [o.evidence_line() for o in objs[:10]]
                     + ["Source: built-in advisory list; confirm on the Fortinet PSIRT site"],
            severity=severity,
            confidence=Confidence.HIGH if enabled else Confidence.MEDIUM,
            exposure=Exposure.INTERNET_FACING if internet else Exposure.MANAGEMENT_PLANE)
