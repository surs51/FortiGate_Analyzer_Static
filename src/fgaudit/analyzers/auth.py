from __future__ import annotations

from ..findings import Category, Confidence, Exposure, Finding
from .access import sslvpn_state
from .base import Analyzer, AnalyzerContext, join_names, plural, register

TWO_FACTOR_VALID = {"fortitoken", "fortitoken-cloud", "email", "sms"}


@register
class AuthAnalyzer(Analyzer):
    name = "authentication"
    category = Category.AUTH

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._ldap(ctx))
        findings.extend(self._remote_users(ctx))
        return findings

    def _ldap(self, ctx: AnalyzerContext) -> list[Finding]:
        out: list[Finding] = []
        for ldap in ctx.model.objects("user ldap", vdom=None):
            if not ldap.name:
                continue
            if ldap.lower("secure", "disable") in ("ldaps", "starttls"):
                continue
            server = ldap.get("server") or "?"
            bind = ldap.get("username")
            who = f"the bind account ({bind}) and user passwords" if bind else "user passwords"
            out.append(ctx.finding(
                "AUTH_LDAP_CLEARTEXT", vdom=ldap.vdom, affected_object=ldap.name,
                description=(f"LDAP server '{ldap.name}' ({server}) is used without LDAPS or "
                             f"STARTTLS, so {who} cross the network in clear text."),
                evidence=[ldap.evidence_line(),
                          f"secure {ldap.lower('secure') or 'disable (the default)'}"],
                confidence=Confidence.HIGH, exposure=Exposure.INTERNAL))
        return out

    def _remote_groups_and_users(self, ctx: AnalyzerContext) -> tuple[set[str], set[str], list[str]]:
        groups: set[str] = set()
        users: set[str] = set()
        paths: list[str] = []
        state = sslvpn_state(ctx)
        if state is not None:
            paths.append("SSL-VPN")
            for rule in state["settings"].child("authentication-rule"):
                groups.update(rule.get_list("groups"))
                users.update(rule.get_list("users"))
        dialup = [p for s in ("vpn ipsec phase1-interface", "vpn ipsec phase1")
                  for p in ctx.model.objects(s, vdom=None)
                  if p.name and p.lower("type") == "dynamic"]
        for p1 in dialup:
            if p1.get("authusrgrp"):
                groups.add(p1.get("authusrgrp"))
                paths.append(f"dial-up IPsec '{p1.name}'")
        if paths:
            for vdom in ctx.model.policy_vdoms:
                for ep in ctx.effective(vdom):
                    if not ep.enabled or not ep.is_allow:
                        continue
                    if any(ctx.resolver.is_remote_access_interface(n)
                           for n in ep.policy.get_list("srcintf")):
                        groups.update(ep.policy.get_list("groups"))
                        users.update(ep.policy.get_list("users"))
        return groups, users, paths

    def _expand_groups(self, ctx: AnalyzerContext, groups: set[str]) -> set[str]:
        members: set[str] = set()
        seen: set[str] = set()
        todo = list(groups)
        while todo:
            name = todo.pop()
            if name in seen:
                continue
            seen.add(name)
            for grp in ctx.model.objects("user group", vdom=None):
                if grp.name != name:
                    continue
                for m in grp.get_list("member"):
                    members.add(m)
                    todo.append(m)
        return members

    def _remote_users(self, ctx: AnalyzerContext) -> list[Finding]:
        groups, users, paths = self._remote_groups_and_users(ctx)
        if not paths:
            return []
        candidates = users | self._expand_groups(ctx, groups)
        weak = []
        vdom = None
        for user in ctx.model.objects("user local", vdom=None):
            if not user.name or user.name not in candidates:
                continue
            if user.lower("status", "enable") == "disable":
                continue
            if user.lower("type", "password") != "password":
                continue
            if user.lower("two-factor", "disable") in TWO_FACTOR_VALID:
                continue
            weak.append(user.name)
            vdom = vdom or user.vdom
        if not weak:
            return []
        names = sorted(weak)
        return [ctx.finding(
            "AUTH_USER_NO_MFA", vdom=vdom or ctx.model.policy_vdoms[0],
            affected_object=join_names(names, 8),
            description=(f"{plural(len(names), 'local user')} can connect through "
                         f"{join_names(paths)} with only a password: {join_names(names, 20)}."),
            evidence=[f"user local / edit {n} (two-factor not set)" for n in names[:10]],
            confidence=Confidence.HIGH, exposure=Exposure.INTERNET_FACING)]
