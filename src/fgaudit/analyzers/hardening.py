from __future__ import annotations

from typing import Iterator, Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..knowledge import WEAK_SSH_ENC_MARKERS, WEAK_SSH_KEX, WEAK_SSH_MAC_MARKERS
from ..models import ROOT_VDOM, ConfigObject
from .access import global_settings
from .base import Analyzer, AnalyzerContext, join_names, plural, register

OLD_ADMIN_TLS = {"tlsv1-0", "tlsv1-1", "sslv3"}
OLD_SSL_MIN = {"sslv3", "tlsv1", "tlsv1-0", "tlsv1-1"}
DEFAULT_COMMUNITIES = {"public", "private", "community", "snmp", "fortinet", "fortigate"}


def _walk(obj: ConfigObject) -> Iterator[ConfigObject]:
    yield obj
    for children in obj.children.values():
        for child in children:
            yield from _walk(child)


def _count_encrypted_secrets(ctx: AnalyzerContext) -> int:
    count = 0
    for top in ctx.model.iter_all():
        for obj in _walk(top):
            for values in obj.settings.values():
                if values and values[0] == "ENC":
                    count += 1
    return count


def _as_int(value: Optional[str], default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


@register
class HardeningAnalyzer(Analyzer):
    name = "hardening"
    category = Category.HARDENING

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        g = global_settings(ctx)
        if g is not None:
            findings.extend(self._global_checks(ctx, g))
        findings.extend(self._usb(ctx, g))
        findings.extend(self._asymroute(ctx))
        findings.extend(self._snmp(ctx))
        findings.extend(self._updates(ctx))
        findings.extend(self._threat_feeds(ctx, g.vdom if g else ROOT_VDOM))
        findings.extend(self._dns(ctx))
        findings.extend(self._ntp(ctx))
        return findings

    def _global_checks(self, ctx: AnalyzerContext, g: ConfigObject) -> list[Finding]:
        out: list[Finding] = []
        gv = g.vdom
        mgmt = Exposure.MANAGEMENT_PLANE

        def add(rule_id: str, desc: str, ev: list[str], *, confidence=Confidence.HIGH,
                exposure=mgmt, severity: Optional[Severity] = None) -> None:
            out.append(ctx.finding(rule_id, vdom=gv, affected_object="system global",
                                   description=desc, evidence=[g.evidence_line()] + ev,
                                   confidence=confidence, exposure=exposure,
                                   severity=severity))

        if g.lower("strong-crypto", "enable") == "disable":
            add("HARDEN_WEAK_CRYPTO",
                "strong-crypto is disabled, so the firewall's own HTTPS, SSH and FortiGuard "
                "connections may use weak ciphers.",
                ["set strong-crypto disable"])

        admin_tls = {v.lower() for v in g.get_list("admin-https-ssl-versions")}
        old_admin = sorted(admin_tls & OLD_ADMIN_TLS)
        ssl_min = g.lower("ssl-min-proto-version")
        problems = []
        if old_admin:
            problems.append(f"the admin interface allows {', '.join(old_admin)}")
        if ssl_min in OLD_SSL_MIN:
            problems.append(f"the firewall's own outgoing TLS accepts {ssl_min} and newer")
        if problems:
            add("HARDEN_TLS_OLD", "Old TLS is still allowed: " + "; ".join(problems) + ".",
                [f"set admin-https-ssl-versions {' '.join(sorted(admin_tls))}"] if old_admin
                else [f"set ssl-min-proto-version {ssl_min}"])

        timeout = _as_int(g.get("admintimeout") or g.get("admin-timeout"), 5)
        if timeout == 0 or timeout > ctx.config.long_admin_timeout:
            shown = "never" if timeout == 0 else f"after {timeout} minutes"
            add("HARDEN_ADMIN_TIMEOUT",
                f"Idle admin sessions time out {shown}. The review's limit is "
                f"{ctx.config.long_admin_timeout} minutes.",
                [f"set admintimeout {timeout}"], confidence=Confidence.MEDIUM)

        if g.lower("security-rating-run-on-schedule") == "disable":
            add("HARDEN_SECURITY_RATING_DISABLED",
                "The scheduled Security Rating run is turned off.",
                ["set security-rating-run-on-schedule disable"],
                confidence=Confidence.MEDIUM, exposure=Exposure.INTERNAL)

        if g.lower("private-data-encryption", "disable") != "enable":
            secrets = _count_encrypted_secrets(ctx)
            if secrets:
                add("HARDEN_PRIVATE_DATA_ENCRYPTION",
                    f"This backup contains {plural(secrets, 'encrypted secret')} (VPN keys, "
                    f"passwords and the like), and private-data-encryption is off, so they "
                    f"are protected only by FortiOS's built-in key.",
                    ["private-data-encryption is not enabled",
                     f"{secrets} values start with ENC"],
                    exposure=Exposure.INTERNAL)

        threshold = _as_int(g.get("admin-lockout-threshold"), 3)
        duration = _as_int(g.get("admin-lockout-duration"), 60)
        if threshold > 5 or duration < 300:
            parts = []
            if threshold > 5:
                parts.append(f"an admin login locks after {threshold} failures")
            if duration < 300:
                parts.append(f"the lockout only lasts {duration} seconds")
            add("HARDEN_ADMIN_LOCKOUT",
                "Admin login lockout is weak: " + " and ".join(parts) + ".",
                [f"admin-lockout-threshold {threshold}", f"admin-lockout-duration {duration}"],
                confidence=Confidence.HIGH if g.is_set("admin-lockout-duration")
                else Confidence.MEDIUM)

        weak_ssh = []
        if g.lower("admin-ssh-v1") == "enable":
            weak_ssh.append("SSH version 1")
        weak_ssh += [a for a in g.get_list("ssh-kex-algo") if a.lower() in WEAK_SSH_KEX]
        weak_ssh += [a for a in g.get_list("ssh-enc-algo")
                     if any(m in a.lower() for m in WEAK_SSH_ENC_MARKERS)]
        weak_ssh += [a for a in g.get_list("ssh-mac-algo")
                     if any(m in a.lower() for m in WEAK_SSH_MAC_MARKERS)]
        if weak_ssh:
            add("HARDEN_SSH_WEAK_ALGO",
                f"Admin SSH still allows {join_names(weak_ssh, 8)}.",
                [f"{k} {' '.join(g.get_list(k))}" for k in
                 ("ssh-kex-algo", "ssh-enc-algo", "ssh-mac-algo") if g.get_list(k)])

        if g.lower("pre-login-banner", "disable") != "enable":
            add("HARDEN_LOGIN_BANNER",
                "No banner is shown before admin login.",
                ["pre-login-banner is not enabled"],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNAL)
        return out

    def _usb(self, ctx: AnalyzerContext, g: Optional[ConfigObject]) -> list[Finding]:
        platform = (ctx.meta.get("platform") or "").upper()
        if not platform or "VM" in platform or platform.startswith(("FOS", "FFW")):
            return []
        auto = ctx.model.first("system auto-install")
        on = []
        if auto is None or auto.lower("auto-install-config", "enable") == "enable":
            on.append("configuration")
        if auto is None or auto.lower("auto-install-image", "enable") == "enable":
            on.append("firmware")
        if not on:
            return []
        return [ctx.finding(
            "HARDEN_USB_AUTO_INSTALL", vdom=(auto or g).vdom if (auto or g) else ROOT_VDOM,
            affected_object="system auto-install",
            description=(f"The firewall will load {' and '.join(on)} from a USB stick at "
                         f"boot."),
            evidence=[auto.evidence_line() if auto
                      else "config system auto-install is at its defaults"],
            confidence=Confidence.HIGH if auto else Confidence.MEDIUM)]

    def _asymroute(self, ctx: AnalyzerContext) -> list[Finding]:
        out = []
        for settings in ctx.model.all_singletons("system settings"):
            on = [k for k in ("asymroute", "asymroute6") if settings.lower(k) == "enable"]
            if on:
                out.append(ctx.finding(
                    "HARDEN_ASYMROUTE", vdom=settings.vdom,
                    affected_object=f"system settings ({settings.vdom})",
                    description=(f"{' and '.join(on)} {'is' if len(on) == 1 else 'are'} "
                                 f"enabled in VDOM {settings.vdom}."),
                    evidence=[settings.evidence_line()] + [f"set {k} enable" for k in on],
                    confidence=Confidence.HIGH))
        return out

    def _snmp(self, ctx: AnalyzerContext) -> list[Finding]:
        sysinfo = ctx.model.first("system snmp sysinfo")
        if not sysinfo or sysinfo.lower("status", "disable") != "enable":
            return []
        listening = [i.name for i in ctx.resolver.interfaces()
                     if "snmp" in {v.lower() for v in i.get_list("allowaccess")}]
        if not listening:
            return []
        out: list[Finding] = []
        for comm in ctx.model.objects("system snmp community", vdom=None):
            if comm.lower("status", "enable") == "disable":
                continue
            if not (comm.flag("query-v1-status", True) or comm.flag("query-v2c-status", True)):
                continue
            name = comm.get("name") or ""
            hosts = comm.child("hosts") + comm.child("hosts6")
            open_hosts = not hosts or any(
                h.text("ip").replace(" ", "") in ("", "0.0.0.00.0.0.0", "0.0.0.0/0", "::/0")
                for h in hosts)
            problems = []
            if name.lower() in DEFAULT_COMMUNITIES:
                problems.append(f"uses the well-known community name '{name}'")
            if open_hosts:
                problems.append("answers queries from any address")
            if not problems:
                continue
            out.append(ctx.finding(
                "HARDEN_SNMP_WEAK", vdom=comm.vdom, affected_object=f"SNMP community {name or comm.name}",
                description=(f"SNMP community '{name or comm.name}' {' and '.join(problems)}. "
                             f"SNMP is reachable on {join_names(listening, 5)}."),
                evidence=[comm.evidence_line()],
                severity=Severity.HIGH if len(problems) == 2 else None,
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))
        for user in ctx.model.objects("system snmp user", vdom=None):
            if not user.name or user.lower("status", "enable") == "disable":
                continue
            level = user.lower("security-level", "no-auth-no-priv")
            problems = []
            if level == "no-auth-no-priv":
                problems.append("has no authentication and no encryption")
            elif level == "auth-no-priv":
                problems.append("isn't encrypted")
            if level != "no-auth-no-priv" and user.lower("auth-proto", "sha") == "md5":
                problems.append("authenticates with MD5")
            if level == "auth-priv" and user.lower("priv-proto", "aes") == "des":
                problems.append("encrypts with DES")
            if problems:
                out.append(ctx.finding(
                    "HARDEN_SNMP_WEAK", vdom=user.vdom, affected_object=f"SNMP user {user.name}",
                    description=f"SNMPv3 user '{user.name}' {' and '.join(problems)}.",
                    evidence=[user.evidence_line(), f"security-level {level}"],
                    confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))
        return out

    def _updates(self, ctx: AnalyzerContext) -> list[Finding]:
        sched = ctx.model.first("system autoupdate schedule")
        if sched is None or sched.lower("status", "enable") != "disable":
            return []
        return [ctx.finding(
            "HARDEN_AUTO_UPDATE_DISABLED", vdom=sched.vdom,
            affected_object="system autoupdate schedule",
            description="Scheduled FortiGuard updates are turned off.",
            evidence=[sched.evidence_line(), "set status disable"],
            confidence=Confidence.HIGH)]

    def _threat_feeds(self, ctx: AnalyzerContext, gv: str) -> list[Finding]:
        if any(o.name for o in ctx.model.objects("system external-resource", vdom=None)):
            return []
        return [ctx.finding(
            "HARDEN_THREAT_FEED_MISSING", vdom=gv, affected_object="system external-resource",
            description="No external threat feeds are configured.",
            evidence=["config system external-resource has no entries"],
            confidence=Confidence.LOW)]

    def _dns(self, ctx: AnalyzerContext) -> list[Finding]:
        dns = ctx.model.first("system dns")
        if dns is None:
            return []
        protocol = dns.lower("protocol", "cleartext")
        dot = dns.lower("dns-over-tls")
        if "dot" in protocol or "doh" in protocol or dot in ("enable", "enforce"):
            return []
        return [ctx.finding(
            "HARDEN_DNS_INSECURE", vdom=dns.vdom, affected_object="system dns",
            description="The firewall resolves names over plain DNS.",
            evidence=[dns.evidence_line(), f"protocol {protocol}"],
            confidence=Confidence.LOW)]

    def _ntp(self, ctx: AnalyzerContext) -> list[Finding]:
        ntp = ctx.model.first("system ntp")
        if ntp is None or ntp.lower("ntpsync", "enable") == "enable":
            return []
        return [ctx.finding(
            "HARDEN_NTP_INSECURE", vdom=ntp.vdom, affected_object="system ntp",
            description="NTP time synchronisation is turned off.",
            evidence=[ntp.evidence_line(), "set ntpsync disable"],
            confidence=Confidence.MEDIUM)]
