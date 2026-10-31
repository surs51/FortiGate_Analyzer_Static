from __future__ import annotations

from typing import Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigObject
from .base import Analyzer, AnalyzerContext, join_names, plural, register

TWO_FACTOR_VALID = {"fortitoken", "fortitoken-cloud", "email", "sms"}
_OPEN_TRUSTHOST = {"0.0.0.00.0.0.0", "0.0.0.0/0", "::/0", "::0", "::"}


def _is_open(value: str) -> bool:
    return value.replace(" ", "") in _OPEN_TRUSTHOST or not value.strip()


def _admin_trusthosts(obj: ConfigObject) -> list[str]:
    hosts: list[str] = []
    for i in range(1, 11):
        for key in (f"trusthost{i}", f"ip6-trusthost{i}"):
            joined = obj.text(key)
            if joined and not _is_open(joined):
                hosts.append(joined)
    return hosts


def _api_trusthosts(obj: ConfigObject) -> list[str]:
    hosts = _admin_trusthosts(obj)
    for entry in obj.child("trusthost"):
        for key in ("ipv4-trustedhost", "ipv6-trustedhost"):
            joined = entry.text(key)
            if joined and not _is_open(joined):
                hosts.append(joined)
    return hosts


def _as_int(val: object) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


@register
class AdminAnalyzer(Analyzer):
    name = "admin"
    category = Category.ADMIN

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._accounts(ctx))
        findings.extend(self._api_users(ctx))
        findings.extend(self._password_policy(ctx))
        findings.extend(self._cleartext_access(ctx))
        return findings

    def _accounts(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        admins = [o for o in ctx.model.objects("system admin", vdom=None) if o.name]
        if not admins:
            return out
        vdom = admins[0].vdom
        local, no_mfa, no_mfa_remote, open_hosts, super_admins = [], [], [], [], []

        for adm in admins:
            profile = (adm.get("accprofile") or "").strip('"')
            remote = adm.flag("remote-auth", False) or bool(adm.get("remote-group"))
            if profile == "super_admin":
                super_admins.append(adm)
            if not remote:
                local.append(adm)
            if adm.lower("two-factor", "disable") not in TWO_FACTOR_VALID:
                (no_mfa_remote if remote else no_mfa).append(adm)
            if not _admin_trusthosts(adm):
                open_hosts.append(adm)
            if adm.flag("wildcard", False):
                out.append(ctx.finding(
                    "ADMIN_WILDCARD_REMOTE", vdom=adm.vdom, affected_object=adm.name,
                    description=(f"Admin entry '{adm.name}' has wildcard enabled, so every "
                                 f"member of remote group '{adm.get('remote-group') or '?'}' "
                                 f"logs in with profile {profile or '?'}."),
                    evidence=[adm.evidence_line(), "set wildcard enable"],
                    severity=Severity.HIGH if profile == "super_admin" else None,
                    confidence=Confidence.HIGH,
                    exposure=Exposure.MANAGEMENT_PLANE))

        def names(objs: list[ConfigObject]) -> str:
            return join_names(sorted(o.name for o in objs))

        if local:
            out.append(ctx.finding(
                "ADMIN_LOCAL_ACCOUNT", vdom=vdom, affected_object=names(local),
                description=(f"{plural(len(local), 'admin account')} "
                             f"{'is' if len(local) == 1 else 'are'} local to the firewall "
                             f"rather than checked against a central directory: {names(local)}."),
                evidence=[a.evidence_line() for a in local[:8]],
                confidence=Confidence.MEDIUM, exposure=Exposure.MANAGEMENT_PLANE))

        if no_mfa:
            out.append(ctx.finding(
                "ADMIN_NO_MFA", vdom=vdom, affected_object=names(no_mfa),
                description=(f"{plural(len(no_mfa), 'admin account')} can log in with a "
                             f"password alone: {names(no_mfa)}."),
                evidence=[a.evidence_line() for a in no_mfa[:8]],
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))
        if no_mfa_remote:
            out.append(ctx.finding(
                "ADMIN_NO_MFA", vdom=vdom, affected_object=names(no_mfa_remote),
                description=(f"{plural(len(no_mfa_remote), 'remote admin account')} "
                             f"({names(no_mfa_remote)}) {'has' if len(no_mfa_remote) == 1 else 'have'} "
                             f"no FortiGate two-factor setting. That's fine if the RADIUS or "
                             f"LDAP server enforces MFA, which this backup can't show."),
                evidence=[a.evidence_line() for a in no_mfa_remote[:8]],
                confidence=Confidence.LOW, exposure=Exposure.MANAGEMENT_PLANE))

        if open_hosts:
            out.append(ctx.finding(
                "ADMIN_NO_TRUSTED_HOST", vdom=vdom, affected_object=names(open_hosts),
                description=(f"{plural(len(open_hosts), 'admin account')} "
                             f"{'has' if len(open_hosts) == 1 else 'have'} no trusted hosts "
                             f"and can log in from any address that reaches the admin "
                             f"interface: {names(open_hosts)}."
                             + (" Because not every account is restricted, trusted hosts "
                                "don't limit who can reach the login page at all."
                                if len(open_hosts) < len(admins) else "")),
                evidence=[a.evidence_line() for a in open_hosts[:8]],
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))

        if len(super_admins) > 1:
            out.append(ctx.finding(
                "ADMIN_MULTIPLE_SUPER_ADMIN", vdom=vdom, affected_object=names(super_admins),
                description=(f"{len(super_admins)} accounts have the super_admin profile: "
                             f"{names(super_admins)}."),
                evidence=[a.evidence_line() for a in super_admins[:8]],
                confidence=Confidence.MEDIUM, exposure=Exposure.MANAGEMENT_PLANE))

        default = next((a for a in admins if a.name == "admin"), None)
        if default is not None:
            out.append(ctx.finding(
                "ADMIN_DEFAULT_NAME", vdom=default.vdom, affected_object="admin",
                description="The factory account name 'admin' is still in use.",
                evidence=[default.evidence_line()],
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))
        return out

    def _api_users(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        for api in ctx.model.objects("system api-user", vdom=None):
            if not api.name:
                continue
            profile = (api.get("accprofile") or "").strip('"')
            problems = []
            if profile == "super_admin":
                problems.append("has the super_admin profile")
            if not _api_trusthosts(api):
                problems.append("can be used from any source address")
            if (api.get("cors-allow-origin") or "").strip() == "*":
                problems.append("allows cross-origin requests from any website")
            if not problems:
                continue
            out.append(ctx.finding(
                "ADMIN_API_EXCESSIVE_PRIV", vdom=api.vdom, affected_object=api.name,
                description=f"API user '{api.name}' {' and '.join(problems)}.",
                evidence=[api.evidence_line()],
                severity=Severity.HIGH if len(problems) > 1 and profile == "super_admin" else None,
                confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE))
        return out

    def _password_policy(self, ctx: AnalyzerContext) -> list[Finding]:
        pol = (ctx.model.singleton("system password-policy", GLOBAL_VDOM)
               or ctx.model.singleton("system password-policy", ROOT_VDOM))
        vdom = pol.vdom if pol else ROOT_VDOM
        problems: list[str] = []
        notes: list[str] = []

        disabled = pol is None or pol.lower("status", "disable") != "enable"
        if disabled:
            problems.append("the admin password policy is turned off")
        else:
            min_len = _as_int(pol.get("minimum-length") or 8)
            if min_len < 8:
                problems.append(f"the minimum length is only {min_len}")
            classes = sum(1 for k in ("min-lower-case-letter", "min-upper-case-letter",
                                      "min-number", "min-non-alphanumeric")
                          if _as_int(pol.get(k)) > 0)
            if classes < 2:
                problems.append("no mix of character types is required")
            if pol.lower("reuse-password", "enable") == "enable":
                notes.append("old passwords can be reused")
            if pol.lower("expire-status", "disable") != "enable":
                notes.append("passwords never expire")

        if not problems:
            return []
        if disabled:
            desc = "The admin password policy is turned off, so any password is accepted."
        else:
            desc = "The admin password rules are weak: " + "; ".join(problems) + "."
        if notes:
            desc += " Also, " + " and ".join(notes) + "."
        return [ctx.finding(
            "ADMIN_WEAK_PASSWORD_POLICY", vdom=vdom, affected_object="system password-policy",
            description=desc,
            evidence=[pol.evidence_line()] if pol else ["config system password-policy is not set"],
            confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE)]

    def _cleartext_access(self, ctx: AnalyzerContext) -> list[Finding]:
        g = _global(ctx)
        redirect = g.flag("admin-https-redirect", True) if g else True
        telnet, http = [], []
        rep_vdom: Optional[str] = None
        for itf in ctx.resolver.interfaces():
            access = {v.lower() for v in itf.get_list("allowaccess")}
            if "telnet" in access:
                telnet.append(itf.name)
            if "http" in access:
                http.append(itf.name)
            rep_vdom = rep_vdom or itf.vdom
        if not telnet and not http:
            return []

        parts = []
        if telnet:
            parts.append(f"Telnet, which sends passwords in clear text, is enabled on "
                         f"{join_names(sorted(telnet))}")
        if http:
            if redirect:
                parts.append(f"HTTP admin access is enabled on {join_names(sorted(http))}. It "
                             f"only redirects to HTTPS, but that first request can be "
                             f"intercepted")
            else:
                parts.append(f"HTTP admin access is enabled on {join_names(sorted(http))} "
                             f"and admin-https-redirect is off, so logins can happen "
                             f"unencrypted")
        severe = bool(telnet) or (bool(http) and not redirect)
        return [ctx.finding(
            "ADMIN_INSECURE_ACCESS", vdom=rep_vdom or ROOT_VDOM,
            affected_object=join_names(sorted(set(telnet) | set(http))),
            description=". ".join(parts) + ".",
            evidence=[f"config system interface / edit {n} (allowaccess includes telnet)"
                      for n in sorted(telnet)]
                     + [f"config system interface / edit {n} (allowaccess includes http)"
                        for n in sorted(http)],
            severity=None if severe else Severity.MEDIUM,
            confidence=Confidence.HIGH, exposure=Exposure.MANAGEMENT_PLANE)]


def _global(ctx: AnalyzerContext) -> Optional[ConfigObject]:
    return (ctx.model.singleton("system global", GLOBAL_VDOM)
            or ctx.model.singleton("system global", ROOT_VDOM)
            or ctx.model.first("system global"))
