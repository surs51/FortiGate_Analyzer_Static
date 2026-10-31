from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from typing import Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..knowledge import (
    RISKY_SERVICE_NAMES,
    RISKY_TCP,
    RISKY_TCP_RANGES,
    RISKY_UDP,
    SSH_PORT,
    TLS_TCP_PORTS,
)
from ..object_resolver import EffectivePolicy
from ..object_resolver.algebra import IntervalSet, ServiceSet, service_to_strings
from .base import Analyzer, AnalyzerContext, and_join, join_names, plural, register

PAYLOAD_UTM = {
    "av-profile": "antivirus",
    "dlp-profile": "DLP",
    "dlp-sensor": "DLP",
    "file-filter-profile": "file filter",
    "emailfilter-profile": "email filter",
    "ips-sensor": "IPS",
}
SNI_UTM = {
    "webfilter-profile": "web filter",
    "dnsfilter-profile": "DNS filter",
    "application-list": "application control",
    "videofilter-profile": "video filter",
    "casb-profile": "CASB",
}
HARD_PAYLOAD = {"av-profile", "dlp-profile", "dlp-sensor", "file-filter-profile",
                "emailfilter-profile"}

_DATE_RE = re.compile(r"(\d{4})/(\d{1,2})/(\d{1,2})")
_CONF = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}
_INTERNAL_ROLES = {"lan", "dmz", "undefined", "vpn"}


def risky_services(service: ServiceSet) -> list[str]:
    if service.is_all() or service.whole_protocols():
        return []
    labels: set[str] = set()
    for port, label in RISKY_TCP.items():
        if service.tcp.covers(port):
            labels.add(label)
    for lo, hi, label in RISKY_TCP_RANGES:
        if service.tcp.intersects(IntervalSet.closed(lo, hi)):
            labels.add(label)
    for port, label in RISKY_UDP.items():
        if service.udp.covers(port):
            labels.add(label)
    for tag in service.opaque:
        tokens = set(re.split(r"[^A-Z0-9-]+", tag.upper()))
        labels |= tokens & RISKY_SERVICE_NAMES
    return sorted(labels)


def carries_encrypted(service: ServiceSet) -> bool:
    if service.is_all() or service.opaque or service.whole_protocols():
        return True
    if service.tcp.covers(SSH_PORT):
        return True
    return any(service.tcp.covers(p) for p in TLS_TCP_PORTS) or bool(service.udp.covers(443))


def _profile_names(profiles: dict[str, str]) -> str:
    if not profiles:
        return "none"
    return ", ".join(f"{k} {v}" for k, v in sorted(profiles.items()))


@dataclass
class Direction:
    kind: str
    confidence: Confidence

    @property
    def internet(self) -> bool:
        return self.kind in ("ingress", "egress")

    def describe(self) -> str:
        return {
            "ingress": "coming in from the internet",
            "egress": "going out to the internet",
            "internal": "between internal networks",
            "intra-zone": "inside one zone",
            "remote-access": "from VPN users into the network",
            "transit": "between two internet-facing interfaces",
            "unknown": "between interfaces whose role is unclear",
        }[self.kind]


@register
class PolicyAnalyzer(Analyzer):
    name = "firewall_policy"
    category = Category.FIREWALL_POLICY

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        for vdom in ctx.model.policy_vdoms:
            eff = ctx.effective(vdom)
            for ep in eff:
                findings.extend(self._analyze_policy(ctx, ep))
            findings.extend(self._ruleset_checks(ctx, vdom, eff))
        return findings

    def _direction(self, ctx: AnalyzerContext, ep: EffectivePolicy) -> Direction:
        pol = ep.policy
        src_names, dst_names = pol.get_list("srcintf"), pol.get_list("dstintf")
        src = ctx.resolver.interface_roles(ep.vdom, src_names)
        dst = ctx.resolver.interface_roles(ep.vdom, dst_names)
        src_wan, dst_wan = "wan" in src, "wan" in dst
        src_any, dst_any = "any" in src, "any" in dst
        src_int, dst_int = bool(src & _INTERNAL_ROLES), bool(dst & _INTERNAL_ROLES)
        has_wan = bool(ctx.wan_names())

        if "remote" in src and not src_wan:
            return Direction("remote-access", Confidence.HIGH)
        if src_wan and not dst_wan and (dst_int or "remote" in dst or dst_any):
            conf = ctx.resolver.wan_confidence_for(ep.vdom, src_names)
            return Direction("ingress", _CONF.get(conf, Confidence.LOW))
        if dst_wan and not src_wan and (src_int or src_any):
            conf = ctx.resolver.wan_confidence_for(ep.vdom, dst_names)
            return Direction("egress", _CONF.get(conf, Confidence.LOW))
        if src_int and dst_int and not (src_wan or dst_wan or src_any or dst_any):
            kind = "intra-zone" if src_names == dst_names else "internal"
            return Direction(kind, Confidence.MEDIUM)
        if src_any and has_wan:
            return Direction("ingress", Confidence.LOW)
        if dst_any and has_wan:
            return Direction("egress", Confidence.LOW)
        if src_wan and dst_wan:
            return Direction("transit", Confidence.LOW)
        if not has_wan and (src_int or src_any) and (dst_int or dst_any):
            return Direction("internal", Confidence.LOW)
        return Direction("unknown", Confidence.LOW)

    def _analyze_policy(self, ctx: AnalyzerContext, ep: EffectivePolicy) -> list[Finding]:
        out: list[Finding] = []
        if not ep.enabled or not ep.is_allow or ep.matches_nothing():
            return out

        pol = ep.policy
        vdom = ep.vdom
        label = ep.label
        base_ev = [pol.evidence_line(), ep.evidence_text()]
        d = self._direction(ctx, ep)
        inbound = d.kind == "ingress"
        remote = d.kind == "remote-access"
        exposure = Exposure.INTERNET_FACING if (d.internet or remote) else Exposure.INTERNAL
        if ep.targets_vip and not d.internet:
            exposure = Exposure.PUBLISHED_SERVICE
        where = d.describe()

        def add(rule_id: str, desc: str, *, severity: Optional[Severity] = None,
                confidence: Confidence = Confidence.MEDIUM,
                exp: Optional[Exposure] = None, extra: Optional[list[str]] = None) -> None:
            out.append(ctx.finding(
                rule_id, vdom=vdom, affected_object=label, description=desc,
                evidence=base_ev + (extra or []), severity=severity,
                confidence=confidence, exposure=exp or exposure))

        service = ep.inbound_service() if inbound else ep.service
        narrowed = inbound and service is not ep.service
        src_all = ep.src_ip.is_broad()
        dst_all = ep.dst_ip.is_broad()
        svc_all = service.is_all()
        whole = service.whole_protocols()
        risky = risky_services(service)

        if remote and (dst_all or svc_all):
            what = ("every destination on every service" if dst_all and svc_all
                    else "every destination" if dst_all else "every service")
            add("VPN_BROAD_ACCESS",
                f"{label} lets VPN users reach {what}.",
                severity=Severity.HIGH if (dst_all and svc_all) else Severity.MEDIUM,
                confidence=Confidence.HIGH)
        elif src_all and dst_all and svc_all:
            add("POLICY_ANY_ANY_ANY",
                f"{label} allows any source to reach any destination on any service, "
                f"for traffic {where}.",
                severity=(Severity.CRITICAL if inbound
                          else Severity.HIGH if d.internet else Severity.MEDIUM),
                confidence=Confidence.HIGH)
        elif dst_all and svc_all:
            add("POLICY_BROAD_DST_SVC",
                f"{label} allows every service to any destination, for traffic {where}.",
                severity=Severity.HIGH if d.internet else Severity.MEDIUM,
                confidence=Confidence.HIGH)
        elif src_all and dst_all:
            add("POLICY_BROAD_SRC_DST",
                f"{label} uses 'all' (or something just as wide) for both source and "
                f"destination, for traffic {where}.",
                confidence=Confidence.HIGH)
        elif src_all and not inbound:
            add("POLICY_BROAD_SRC",
                f"{label} accepts any source address, for traffic {where}.")
        elif svc_all:
            add("POLICY_SERVICE_ALL",
                f"{label} allows all services, for traffic {where}.",
                severity=Severity.MEDIUM if d.internet else Severity.LOW)
        elif whole:
            add("POLICY_SERVICE_ALL_PROTO",
                f"{label} allows every {' and '.join(whole)} port, for traffic {where}.")

        if narrowed and ep.service.is_all():
            forwarded = ", ".join(service_to_strings(service))
            add("POLICY_SERVICE_ALL",
                f"{label} is set to service ALL. Its VIP only forwards {forwarded}, so "
                f"that's all that gets through today, but if the VIP is ever changed to "
                f"forward every port, this rule will let all of it in.",
                severity=Severity.LOW, confidence=Confidence.HIGH)

        if ep.src_intf.is_any or ep.dst_intf.is_any:
            side = ("source and destination" if ep.src_intf.is_any and ep.dst_intf.is_any
                    else "source" if ep.src_intf.is_any else "destination")
            add("POLICY_INTERFACE_ANY",
                f"{label} uses 'any' as its {side} interface, so it applies on every "
                f"interface pair.",
                severity=Severity.HIGH if d.internet else Severity.MEDIUM)

        profiles = ep.profile_map()
        if ep.profiles and not ep.utm_enabled:
            add("POLICY_UTM_DISABLED",
                f"{label} has profiles attached ({_profile_names(ep.profiles)}) but "
                f"utm-status is disabled, so none of them run.",
                confidence=Confidence.HIGH)

        from_internet_side = ctx.is_wan_intf_set(ep.src_intf)
        if not profiles:
            if not from_internet_side and (d.internet or remote or src_all or dst_all or svc_all):
                sev = Severity.HIGH if (d.internet and (dst_all or svc_all)) else Severity.MEDIUM
                add("POLICY_NO_UTM",
                    f"{label} allows traffic {where} without any security profile.",
                    severity=sev, confidence=Confidence.HIGH)
        else:
            depth = ctx.resolver.ssl_depth(vdom, ep.ssl_profile)
            encrypted = carries_encrypted(service)
            payload = {k: v for k, v in profiles.items() if k in PAYLOAD_UTM}
            sni = {k: v for k, v in profiles.items() if k in SNI_UTM}
            ssl_name = ep.ssl_profile or "no-inspection (the default)"
            if payload and encrypted:
                scanners = and_join(sorted({PAYLOAD_UTM[k] for k in payload}))
                if depth in ("cert", "none"):
                    mode = ("only does certificate inspection" if depth == "cert"
                            else "doesn't inspect encrypted traffic at all")
                    add("POLICY_SSL_INEFFECTIVE_PAYLOAD",
                        f"{label} relies on {scanners}, but its SSL profile ({ssl_name}) "
                        f"{mode}. Encrypted content passes these scanners unseen.",
                        severity=(Severity.HIGH if any(k in payload for k in HARD_PAYLOAD)
                                  else Severity.MEDIUM),
                        confidence=Confidence.HIGH)
                elif depth == "unknown":
                    add("POLICY_SSL_UNKNOWN",
                        f"{label} relies on {scanners} with SSL profile {ssl_name}, whose "
                        f"inspection mode isn't visible in this backup.",
                        confidence=Confidence.LOW)
            if sni and not payload and depth == "none" and encrypted:
                names = and_join(sorted({SNI_UTM[k] for k in sni}))
                add("POLICY_SSL_INEFFECTIVE_SNI",
                    f"{label} uses {names} with SSL profile {ssl_name}, which inspects "
                    f"nothing. HTTPS sites mostly slip past these filters.")

        if inbound:
            if dst_all or svc_all or whole:
                what = ("every service" if svc_all
                        else f"every {' and '.join(whole)} port" if whole
                        else "every internal address")
                add("POLICY_WAN_EXPOSURE",
                    f"{label} lets internet traffic reach {what}.",
                    confidence=d.confidence, exp=Exposure.INTERNET_FACING)
            elif risky:
                add("POLICY_WAN_EXPOSURE",
                    f"{label} lets internet traffic reach {', '.join(risky)}.",
                    confidence=d.confidence, exp=Exposure.INTERNET_FACING)
        elif risky and (src_all or d.kind == "egress"):
            who = "to the internet" if d.kind == "egress" else "from any source"
            add("POLICY_RISKY_SERVICE",
                f"{label} allows {', '.join(risky)} {who}.")

        if pol.lower("logtraffic") == "disable":
            add("POLICY_LOGGING_DISABLED",
                f"{label} allows traffic {where} with logging turned off.",
                severity=Severity.MEDIUM if d.internet else Severity.LOW,
                confidence=Confidence.HIGH)

        sched = pol.get("schedule")
        if sched:
            ended = self._schedule_end(ctx, vdom, sched)
            if ended is not None and ended < ctx.today:
                add("POLICY_EXPIRED_SCHEDULE",
                    f"{label} uses schedule '{sched}', which ended on {ended.isoformat()}. "
                    f"The rule can't match anymore.",
                    confidence=Confidence.HIGH, exp=Exposure.INTERNAL)
        return out

    def _schedule_end(self, ctx: AnalyzerContext, vdom: str, name: str,
                      _seen: Optional[set[str]] = None) -> Optional[_dt.date]:
        obj = ctx.sets.find(vdom, "firewall schedule onetime", name)
        if obj is not None:
            m = _DATE_RE.search(obj.text("end"))
            if not m:
                return None
            try:
                return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
        grp = ctx.sets.find(vdom, "firewall schedule group", name)
        if grp is None:
            return None
        seen = _seen or set()
        if name in seen:
            return None
        seen.add(name)
        ends = [self._schedule_end(ctx, vdom, m, seen) for m in grp.get_list("member")]
        if not ends or any(e is None for e in ends):
            return None
        return max(ends)

    def _ruleset_checks(self, ctx: AnalyzerContext, vdom: str,
                        eff: list[EffectivePolicy]) -> list[Finding]:
        out: list[Finding] = []
        if not eff:
            return out

        if len(eff) >= ctx.config.excessive_policy_count:
            out.append(ctx.finding(
                "POLICY_EXCESSIVE_COUNT", vdom=vdom, affected_object=f"VDOM {vdom}",
                description=(f"VDOM {vdom} has {len(eff)} rules (the review flags anything "
                             f"over {ctx.config.excessive_policy_count})."),
                confidence=Confidence.HIGH))

        active = [ep for ep in eff if ep.enabled and not ep.matches_nothing()]
        out.extend(self._hygiene_aggregates(ctx, vdom, eff))
        dup_ids: set[str] = set()
        out.extend(self._duplicates(ctx, vdom, active, dup_ids))
        if len(active) <= ctx.config.shadow_scan_limit:
            out.extend(self._shadows(ctx, vdom, active, dup_ids))
        elif ctx.coverage is not None:
            ctx.coverage.warnings.append(
                f"VDOM {vdom} has {len(active)} active rules, more than the shadow scan "
                f"limit of {ctx.config.shadow_scan_limit}, so shadowed and conflicting rules "
                f"weren't checked. Duplicates were. Raise --shadow-scan-limit to include it.")
        if not ctx.resolver.central_nat(vdom):
            out.extend(self._deny_skips_vip(ctx, vdom, active))
        out.extend(self._dead_rules(ctx, vdom, eff))
        return out

    def _hygiene_aggregates(self, ctx: AnalyzerContext, vdom: str,
                            eff: list[EffectivePolicy]) -> list[Finding]:
        out: list[Finding] = []

        def agg(rule_id: str, ids: list[str], one: str, many: str, *,
                severity: Optional[Severity] = None,
                confidence: Confidence = Confidence.HIGH) -> None:
            if not ids:
                return
            desc = one.format(id=ids[0]) if len(ids) == 1 else many.format(
                n=len(ids), ids=join_names(ids, 15))
            out.append(ctx.finding(
                rule_id, vdom=vdom,
                affected_object=f"{plural(len(ids), 'rule')} in VDOM {vdom}",
                description=desc,
                evidence=[f"policy ids: {', '.join(ids)}"],
                severity=severity, confidence=confidence))

        agg("POLICY_DISABLED", [ep.policyid for ep in eff if not ep.enabled],
            "Rule {id} is disabled but still in the table.",
            "{n} rules are disabled but still in the table: {ids}.")

        active = [ep for ep in eff if ep.enabled]
        agg("POLICY_NO_NAME", [ep.policyid for ep in active if not ep.name],
            "Rule {id} has no name.",
            "{n} rules have no name: {ids}.")
        agg("POLICY_NO_COMMENT",
            [ep.policyid for ep in active
             if not (ep.policy.get("comments") or ep.policy.get("comment"))],
            "Rule {id} has no comment.",
            "{n} rules have no comment: {ids}.")

        narrow_naked = []
        for ep in active:
            if not ep.is_allow or ep.has_profiles() or ep.matches_nothing():
                continue
            if ep.src_ip.is_broad() or ep.dst_ip.is_broad() or ep.service.is_all():
                continue
            if ctx.is_wan_intf_set(ep.src_intf) or ctx.is_wan_intf_set(ep.dst_intf):
                continue
            if any(ctx.resolver.is_remote_access_interface(n) for n in ep.src_intf.names):
                continue
            narrow_naked.append(ep.policyid)
        agg("POLICY_NO_UTM", narrow_naked,
            "Rule {id} allows narrow internal traffic without any security profile. That's "
            "low risk on its own, but worth knowing when you judge east-west inspection.",
            "{n} rules allow narrow internal traffic without any security profile: {ids}. "
            "Each one is low risk on its own, but together they show how much east-west "
            "traffic goes uninspected.",
            severity=Severity.LOW, confidence=Confidence.MEDIUM)
        return out

    @staticmethod
    def _match_key(ep: EffectivePolicy) -> tuple:
        return (ep.src_intf, ep.dst_intf, ep.src_ip, ep.dst_ip, ep.service,
                ep.action, ep.schedule, ep.identity, ep.l7, ep.targets_vip)

    @staticmethod
    def _treatment_diff(a: EffectivePolicy, b: EffectivePolicy) -> list[str]:
        diffs: list[str] = []
        pa, pb = a.policy, b.policy
        if a.schedule != b.schedule:
            diffs.append("schedule")
        if a.nat != b.nat:
            diffs.append("NAT")
        if set(pa.get_list("poolname")) != set(pb.get_list("poolname")):
            diffs.append("NAT pool")
        if a.treatment_key() != b.treatment_key():
            diffs.append("security profiles")
        if pa.lower("logtraffic") != pb.lower("logtraffic"):
            diffs.append("logging")
        return diffs

    def _duplicates(self, ctx: AnalyzerContext, vdom: str,
                    active: list[EffectivePolicy], dup_ids: set[str]) -> list[Finding]:
        out: list[Finding] = []
        by_match: dict[tuple, EffectivePolicy] = {}
        for ep in active:
            key = self._match_key(ep)
            first = by_match.get(key)
            if first is None:
                by_match[key] = ep
                continue
            dup_ids.add(ep.policyid)
            diffs = self._treatment_diff(first, ep)
            ev = [ep.policy.evidence_line(), first.policy.evidence_line(), ep.evidence_text()]
            if not diffs:
                out.append(ctx.finding(
                    "POLICY_DUPLICATE", vdom=vdom, affected_object=ep.label,
                    description=(f"{ep.label} is an exact copy of {first.label}: same "
                                 f"traffic, same action, same NAT, inspection and logging. "
                                 f"{ep.short.capitalize()} never gets used."),
                    evidence=ev, confidence=Confidence.HIGH))
            else:
                out.append(ctx.finding(
                    "POLICY_NEAR_DUPLICATE", vdom=vdom, affected_object=ep.label,
                    description=(f"{ep.label} matches the same traffic as {first.label} "
                                 f"but differs in {', '.join(diffs)}. Only {first.short} "
                                 f"ever applies."),
                    evidence=ev, confidence=Confidence.LOW))
        return out

    def _shadows(self, ctx: AnalyzerContext, vdom: str,
                 active: list[EffectivePolicy], dup_ids: set[str]) -> list[Finding]:
        out: list[Finding] = []
        shadowed_ids: set[str] = set()

        for idx_j, j in enumerate(active):
            if j.policyid in dup_ids:
                continue
            for i in active[:idx_j]:
                if i.fully_covers(j):
                    shadowed_ids.add(j.policyid)
                    out.append(self._shadow_finding(ctx, vdom, i, j))
                    break

        for idx_j, j in enumerate(active):
            if j.action != "deny" or j.policyid in shadowed_ids:
                continue
            for i in active[:idx_j]:
                if i.is_allow and i.intersects(j) and not i.fully_covers(j):
                    out.append(ctx.finding(
                        "POLICY_DENY_PARTIAL_OVERLAP", vdom=vdom, affected_object=j.label,
                        description=(f"{i.label} comes first and allows part of the traffic "
                                     f"that {j.label} is meant to block. That overlap is "
                                     f"allowed; the block only applies to the rest."),
                        evidence=[j.policy.evidence_line(), i.policy.evidence_line(),
                                  f"block rule: {j.evidence_text()}",
                                  f"earlier allow: {i.evidence_text()}"],
                        confidence=Confidence.MEDIUM,
                        exposure=ctx.exposure_for(j)))
                    break
        return out

    def _shadow_finding(self, ctx: AnalyzerContext, vdom: str,
                        i: EffectivePolicy, j: EffectivePolicy) -> Finding:
        exposure = ctx.exposure_for(j)
        ev = [j.policy.evidence_line(), i.policy.evidence_line(),
              f"never reached: {j.evidence_text()}",
              f"matched first: {i.evidence_text()}"]

        if (i.action == "deny") != (j.action == "deny"):
            outcome = ("the traffic it's meant to block is allowed" if j.action == "deny"
                       else "the traffic it's meant to allow is blocked")
            return ctx.finding(
                "POLICY_SHADOW_CONFLICT", vdom=vdom, affected_object=j.label,
                description=(f"{j.label} ({j.action}) sits below {i.label} ({i.action}), "
                             f"and {i.short} already matches every packet {j.short} would. "
                             f"FortiGate uses the first match, so {j.short} never takes "
                             f"effect and {outcome}."),
                evidence=ev, confidence=Confidence.HIGH, exposure=exposure)

        if j.is_allow and i.treatment_key() != j.treatment_key():
            lost = self._lost_profiles(i, j)
            return ctx.finding(
                "POLICY_SHADOW_PROFILES", vdom=vdom, affected_object=j.label,
                description=(f"{i.label} sits above {j.label} and matches all of its "
                             f"traffic, so that traffic always gets {i.short}'s inspection "
                             f"({_profile_names(i.profile_map())}). The profiles on "
                             f"{j.short} ({lost}) are never used."),
                evidence=ev, confidence=Confidence.HIGH, exposure=exposure)

        return ctx.finding(
            "POLICY_SHADOWED", vdom=vdom, affected_object=j.label,
            description=(f"{i.label} sits above {j.label} and already matches everything "
                         f"{j.short} would, with the same action and inspection. {j.short} "
                         f"never matches anything."),
            evidence=ev, confidence=Confidence.HIGH, exposure=exposure)

    @staticmethod
    def _lost_profiles(i: EffectivePolicy, j: EffectivePolicy) -> str:
        jp, ip = j.profile_map(), i.profile_map()
        diff = [f"{k} {v}" for k, v in jp.items() if v != ip.get(k)]
        if j.ssl_profile and j.ssl_profile != i.ssl_profile:
            diff.append(f"ssl-ssh-profile {j.ssl_profile}")
        return ", ".join(diff) or "a different profile set"

    def _deny_skips_vip(self, ctx: AnalyzerContext, vdom: str,
                        active: list[EffectivePolicy]) -> list[Finding]:
        out: list[Finding] = []
        vip_rules = [ep for ep in active if ep.is_allow and ep.targets_vip]
        if not vip_rules:
            return out
        for deny in active:
            if deny.action != "deny" or deny.targets_vip or deny.match_vip:
                continue
            if not ctx.is_wan_intf_set(deny.src_intf):
                continue
            hit_rules: list[EffectivePolicy] = []
            hit_vips: set[str] = set()
            for rule in vip_rules:
                if not (rule.src_intf.intersects(deny.src_intf)
                        and rule.src_ip.overlaps(deny.src_ip)
                        and rule.service.overlaps(deny.service)):
                    continue
                vips = [v.name for v in rule.vips if v.external.overlaps(deny.dst_ip)]
                if vips:
                    hit_rules.append(rule)
                    hit_vips.update(vips)
            if not hit_rules:
                continue
            source = ", ".join(deny.src_display) or "the listed sources"
            out.append(ctx.finding(
                "POLICY_DENY_SKIPS_VIP", vdom=vdom, affected_object=deny.label,
                description=(f"{deny.label} blocks traffic from {source}, and its "
                             f"destination includes the external address of "
                             f"{join_names(sorted(hit_vips), 5)}. match-vip is off, so the "
                             f"block never sees traffic to those VIPs and "
                             f"{join_names([r.label for r in hit_rules], 5)} still let it in."),
                evidence=[deny.policy.evidence_line(), deny.evidence_text(),
                          "set match-vip is not enabled"]
                         + [r.policy.evidence_line() for r in hit_rules[:5]],
                confidence=Confidence.MEDIUM,
                exposure=Exposure.PUBLISHED_SERVICE))
        return out

    def _dead_rules(self, ctx: AnalyzerContext, vdom: str,
                    eff: list[EffectivePolicy]) -> list[Finding]:
        if ctx.hit_counts is None:
            return []
        zero = [ep.policyid for ep in eff
                if ep.enabled and ctx.hits_for(vdom, ep.policyid) == 0]
        if not zero:
            return []
        return [ctx.finding(
            "POLICY_ZERO_HIT", vdom=vdom,
            affected_object=f"{plural(len(zero), 'enabled rule')}",
            description=(f"{plural(len(zero), 'enabled rule')} show zero hits in the counters "
                         f"you supplied: {join_names(zero, 20)}."),
            evidence=[f"policy ids with zero hits: {', '.join(zero)}"],
            confidence=Confidence.MEDIUM)]
