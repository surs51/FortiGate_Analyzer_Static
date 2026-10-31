from __future__ import annotations

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..models import ConfigObject
from .access import sslvpn_state
from .base import Analyzer, AnalyzerContext, and_join, join_names, register

WEAK_ENC = {"des", "3des"}
WEAK_HASH = {"md5", "sha1", "prfsha1"}
WEAK_DH = {"1", "2", "5", "22"}
OBSOLETE_TLS = {"tls1-0", "tls1-1", "ssl3", "tls1-0-1-1", "tlsv1-0", "tlsv1-1"}
FACTORY_CERTS = {"fortinet_factory", "self-sign", "fortinet_ssl", "fortinet_gui_server"}

PHASE1_SECTIONS = ("vpn ipsec phase1-interface", "vpn ipsec phase1")
PHASE2_SECTIONS = ("vpn ipsec phase2-interface", "vpn ipsec phase2")


def _weak_proposal_parts(proposal: str) -> list[str]:
    found: list[str] = []
    for token in proposal.lower().split():
        for part in token.split("-"):
            if (part in WEAK_ENC or part in WEAK_HASH) and part not in found:
                found.append("sha1" if part == "prfsha1" else part)
    return sorted(set(found))


@register
class VpnAnalyzer(Analyzer):
    name = "vpn"
    category = Category.VPN

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        for section in PHASE1_SECTIONS:
            for obj in ctx.model.objects(section, vdom=None):
                if obj.name:
                    findings.extend(self._phase1(ctx, obj))
        for section in PHASE2_SECTIONS:
            for obj in ctx.model.objects(section, vdom=None):
                if obj.name:
                    findings.extend(self._crypto(ctx, obj, "phase 2", obj.get("phase1name")))
                    findings.extend(self._phase2(ctx, obj))
        findings.extend(self._ssl_vpn(ctx))
        return findings

    def _tunnel_label(self, obj: ConfigObject) -> str:
        kind = "dial-up tunnel" if obj.lower("type") == "dynamic" else "tunnel"
        return f"IPsec {kind} '{obj.name}'"

    def _phase1(self, ctx: AnalyzerContext, obj: ConfigObject) -> list[Finding]:
        out: list[Finding] = []
        label = self._tunnel_label(obj)
        ike = (obj.get("ike-version") or "1").strip()
        if ike == "1":
            out.append(ctx.finding(
                "VPN_IKEV1", vdom=obj.vdom, affected_object=obj.name,
                description=f"{label} uses IKEv1.",
                evidence=[obj.evidence_line(),
                          "ike-version 1" + ("" if obj.get("ike-version") else " (the default)")],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING))
            psk = obj.lower("authmethod", "psk") == "psk"
            if obj.lower("mode", "main") == "aggressive" and psk:
                out.append(ctx.finding(
                    "VPN_AGGRESSIVE_MODE", vdom=obj.vdom, affected_object=obj.name,
                    description=(f"{label} uses IKEv1 aggressive mode with a pre-shared key. "
                                 f"Anyone who can reach the gateway can collect a hash of the "
                                 f"key and try to crack it offline."),
                    evidence=[obj.evidence_line(), "set mode aggressive", "authmethod psk"],
                    confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING))
        out.extend(self._crypto(ctx, obj, "phase 1", None))
        return out

    def _crypto(self, ctx: AnalyzerContext, obj: ConfigObject, phase: str,
                parent: str | None) -> list[Finding]:
        out: list[Finding] = []
        where = f"IPsec {phase} '{obj.name}'" + (f" (tunnel {parent})" if parent else "")
        weak_dh = sorted(set(obj.get_list("dhgrp")) & WEAK_DH, key=int)
        if weak_dh:
            out.append(ctx.finding(
                "VPN_WEAK_DH", vdom=obj.vdom, affected_object=obj.name,
                description=(f"{where} allows Diffie-Hellman "
                             f"group{'s' if len(weak_dh) > 1 else ''} {and_join(weak_dh)}."),
                evidence=[obj.evidence_line(), f"set dhgrp {' '.join(obj.get_list('dhgrp'))}"],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING))
        proposal = " ".join(obj.get_list("proposal"))
        weak = _weak_proposal_parts(proposal)
        if weak:
            out.append(ctx.finding(
                "VPN_WEAK_CIPHER", vdom=obj.vdom, affected_object=obj.name,
                description=f"{where} still offers {and_join(w.upper() for w in weak)}.",
                evidence=[obj.evidence_line(), f"set proposal {proposal}"],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING))
        return out

    def _phase2(self, ctx: AnalyzerContext, obj: ConfigObject) -> list[Finding]:
        problems = []
        if obj.lower("pfs", "enable") == "disable":
            problems.append("perfect forward secrecy is off")
        if obj.lower("replay", "enable") == "disable":
            problems.append("replay detection is off")
        if not problems:
            return []
        return [ctx.finding(
            "VPN_PHASE2_WEAK", vdom=obj.vdom, affected_object=obj.name,
            description=(f"On IPsec phase 2 '{obj.name}' (tunnel "
                         f"{obj.get('phase1name') or '?'}), {' and '.join(problems)}."),
            evidence=[obj.evidence_line()]
                     + [f"set {k} disable" for k in ("pfs", "replay") if obj.lower(k) == "disable"],
            confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING)]

    def _ssl_vpn(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        state = sslvpn_state(ctx)
        if state is None:
            return out
        settings: ConfigObject = state["settings"]
        vdom = settings.vdom
        version = ctx.version
        version_text = str(version) if version else "an unknown version"

        if state["wan"]:
            intfs = join_names(state["interfaces"]) or "every interface (no source-interface set)"
            desc = (f"SSL-VPN is enabled on {intfs}, which faces the internet, and the "
                    f"firewall runs FortiOS {version_text}.")
            if not state["restricted"]:
                desc += " Any source address can reach the login page."
            portals = [p for p in ctx.model.objects("vpn ssl web portal", vdom=None)
                       if p.name and p.flag("web-mode", False)]
            if portals:
                desc += (f" Web mode is on in portal {join_names([p.name for p in portals], 4)}, "
                         f"which puts more code within reach of the internet.")
            out.append(ctx.finding(
                "VPN_SSLVPN_WAN_PORTAL", vdom=vdom, affected_object="vpn ssl settings",
                description=desc,
                evidence=[settings.evidence_line(),
                          f"source-interface {' '.join(state['interfaces']) or '(any)'}",
                          f"source-address {' '.join(settings.get_list('source-address')) or '(any)'}"],
                severity=Severity.MEDIUM if state["restricted"] else None,
                confidence=Confidence.MEDIUM, exposure=Exposure.INTERNET_FACING))

        min_tls = settings.lower("ssl-min-proto-ver")
        weak_tls = []
        tls_conf = Confidence.HIGH
        if min_tls in OBSOLETE_TLS:
            weak_tls.append(f"accepts {min_tls}")
        elif not min_tls and version is not None and not version.at_least(6, 2):
            weak_tls.append(f"falls back to the FortiOS {version} default, which still "
                            f"accepts TLS 1.1")
            tls_conf = Confidence.MEDIUM
        if settings.lower("algorithm") == "low":
            weak_tls.append("allows low-strength ciphers (algorithm low)")
        if weak_tls:
            out.append(ctx.finding(
                "VPN_SSL_WEAK_TLS", vdom=vdom, affected_object="vpn ssl settings",
                description="SSL-VPN " + " and ".join(weak_tls) + ".",
                evidence=[settings.evidence_line(),
                          f"ssl-min-proto-ver {min_tls or '(not set)'}",
                          f"algorithm {settings.lower('algorithm') or '(not set)'}"],
                confidence=tls_conf, exposure=Exposure.INTERNET_FACING))

        cert = settings.lower("servercert", "fortinet_factory").strip('"')
        if cert in FACTORY_CERTS:
            out.append(ctx.finding(
                "VPN_SSL_DEFAULT_CERT", vdom=vdom, affected_object="vpn ssl settings",
                description=(f"The SSL-VPN portal presents the factory certificate "
                             f"'{settings.get('servercert') or 'Fortinet_Factory'}'."),
                evidence=[settings.evidence_line(),
                          f"servercert {settings.get('servercert') or '(not set, Fortinet_Factory)'}"],
                confidence=Confidence.HIGH if settings.get("servercert") else Confidence.MEDIUM,
                exposure=Exposure.INTERNET_FACING))

        attempts = settings.get("login-attempt-limit")
        block = settings.get("login-block-time")
        problems = []
        if attempts == "0":
            problems.append("failed logins are never counted (login-attempt-limit 0)")
        if block == "0":
            problems.append("blocked clients are let back in immediately (login-block-time 0)")
        if problems:
            out.append(ctx.finding(
                "VPN_SSL_BRUTE_FORCE", vdom=vdom, affected_object="vpn ssl settings",
                description="On the SSL-VPN, " + " and ".join(problems) + ".",
                evidence=[settings.evidence_line()],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING))

        for portal in ctx.model.objects("vpn ssl web portal", vdom=None):
            if portal.name and portal.lower("split-tunneling") == "enable" \
                    and portal.lower("tunnel-mode", "disable") == "enable":
                out.append(ctx.finding(
                    "VPN_SSL_SPLIT_TUNNEL", vdom=portal.vdom, affected_object=portal.name,
                    description=f"SSL-VPN portal '{portal.name}' uses split tunnelling.",
                    evidence=[portal.evidence_line(), "set split-tunneling enable"],
                    confidence=Confidence.MEDIUM, exposure=Exposure.INTERNET_FACING))
        return out
