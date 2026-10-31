from __future__ import annotations

import ipaddress

from ..findings import Category, Confidence, Finding
from ..knowledge import PREDEFINED_ADDRESSES, PREDEFINED_SERVICES
from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigObject
from ..object_resolver.reference_index import ADDRESS, VIP
from .base import Analyzer, AnalyzerContext, join_names, plural, register

ADDR_SECTIONS = ("firewall address", "firewall address6")
GRP_SECTIONS = ("firewall addrgrp", "firewall addrgrp6")
OVERLAP_SCAN_LIMIT = 2000


def _is_used(ctx: AnalyzerContext, used: set[tuple[str, str]], vdom: str, name: str) -> bool:
    if (vdom, name) in used:
        return True
    shared = vdom == GLOBAL_VDOM or (vdom == ROOT_VDOM and not ctx.model.multi_vdom)
    return shared and any(n == name for _v, n in used)


@register
class ObjectAnalyzer(Analyzer):
    name = "objects"
    category = Category.OBJECTS

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        vdoms = list(dict.fromkeys(ctx.model.vdoms + ([GLOBAL_VDOM] if ctx.model.multi_vdom else [])))
        for vdom in vdoms:
            findings.extend(self._unused(ctx, vdom))
            findings.extend(self._empty_groups(ctx, vdom))
            findings.extend(self._group_depth(ctx, vdom))
            findings.extend(self._subnet_overlaps(ctx, vdom))
            findings.extend(self._orphan_vips(ctx, vdom))
        return findings

    def _unused(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        res = ctx.resolver
        cc = ctx.coverage_confidence_for(ADDRESS)

        addresses = [o for s in ADDR_SECTIONS for o in ctx.model.local_objects(s, vdom)
                     if o.name and o.name not in PREDEFINED_ADDRESSES
                     and o.lower("type") != "interface-subnet"
                     and not _is_used(ctx, res.used_addresses, vdom, o.name)]
        services = [o for o in ctx.model.local_objects("firewall service custom", vdom)
                    if o.name and o.name not in PREDEFINED_SERVICES
                    and not _is_used(ctx, res.used_services, vdom, o.name)]
        pools = [o for o in ctx.model.local_objects("firewall ippool", vdom)
                 if o.name and not _is_used(ctx, res.used_ippools, vdom, o.name)]

        for rule_id, objs, noun in (("OBJ_UNUSED_ADDRESS", addresses, "address object"),
                                    ("OBJ_UNUSED_SERVICE", services, "custom service"),
                                    ("OBJ_ORPHAN_IPPOOL", pools, "IP pool")):
            if not objs:
                continue
            names = sorted(o.name for o in objs)
            out.append(ctx.finding(
                rule_id, vdom=vdom,
                affected_object=f"{plural(len(names), noun)} in VDOM {vdom}",
                description=(f"{plural(len(names), noun)} in VDOM {vdom} "
                             f"{'is' if len(names) == 1 else 'are'} not referenced anywhere "
                             f"this review looks (rules, groups, routes, VPN and SD-WAN "
                             f"settings): {join_names(names, 25)}."),
                evidence=[o.evidence_line() for o in objs[:10]],
                confidence=Confidence.MEDIUM,
                coverage_confidence=cc))
        return out

    def _empty_groups(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        for sections, label in ((GRP_SECTIONS, "Address group"),
                                (("firewall service group",), "Service group")):
            for section in sections:
                for obj in ctx.model.local_objects(section, vdom):
                    if not obj.name or obj.get_list("member"):
                        continue
                    out.append(ctx.finding(
                        "OBJ_EMPTY_GROUP", vdom=vdom, affected_object=obj.name,
                        description=f"{label} '{obj.name}' has no members.",
                        evidence=[obj.evidence_line()],
                        confidence=Confidence.HIGH))
        return out

    def _group_depth(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        limit = ctx.config.max_group_depth
        for sections in (GRP_SECTIONS, ("firewall service group",)):
            members: dict[str, list[str]] = {}
            objs: dict[str, ConfigObject] = {}
            for section in sections:
                for obj in ctx.model.local_objects(section, vdom):
                    if obj.name:
                        members[obj.name] = obj.get_list("member")
                        objs[obj.name] = obj

            def depth(name: str, seen: frozenset[str]) -> int:
                if name in seen:
                    return 0
                child_groups = [m for m in members.get(name, []) if m in members]
                if not child_groups:
                    return 1
                return 1 + max(depth(c, seen | {name}) for c in child_groups)

            for name, obj in objs.items():
                d = depth(name, frozenset())
                if d > limit:
                    out.append(ctx.finding(
                        "OBJ_NESTED_GROUP_DEPTH", vdom=vdom, affected_object=name,
                        description=(f"Group '{name}' is nested {d} levels deep (the review "
                                     f"flags anything over {limit})."),
                        evidence=[obj.evidence_line()],
                        confidence=Confidence.HIGH))
        return out

    def _subnet_overlaps(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        out: list[Finding] = []
        entries: list[tuple[str, ipaddress._BaseNetwork, ConfigObject]] = []
        for section in ADDR_SECTIONS:
            for obj in ctx.model.local_objects(section, vdom):
                if not obj.name or obj.name in PREDEFINED_ADDRESSES:
                    continue
                nets = ctx.resolver.address_networks(vdom, obj.name)
                if len(nets) == 1 and nets[0].prefixlen != 0:
                    entries.append((obj.name, nets[0], obj))

        by_net: dict[str, list[tuple[str, ConfigObject]]] = {}
        for name, net, obj in entries:
            by_net.setdefault(str(net), []).append((name, obj))
        for net_str, group in by_net.items():
            if len(group) > 1:
                names = ", ".join(sorted(n for n, _ in group))
                out.append(ctx.finding(
                    "OBJ_DUPLICATE_ADDRESS", vdom=vdom, affected_object=names,
                    description=f"{len(group)} address objects all define {net_str}: {names}.",
                    evidence=[o.evidence_line() for _, o in group[:6]],
                    confidence=Confidence.HIGH))

        if len(entries) <= OVERLAP_SCAN_LIMIT:
            for i in range(len(entries)):
                name_a, net_a, obj_a = entries[i]
                for j in range(i + 1, len(entries)):
                    name_b, net_b, obj_b = entries[j]
                    if net_a.version != net_b.version or net_a == net_b:
                        continue
                    if net_a.subnet_of(net_b) or net_b.subnet_of(net_a):
                        inner, outer = ((name_a, net_a), (name_b, net_b)) \
                            if net_a.subnet_of(net_b) else ((name_b, net_b), (name_a, net_a))
                        out.append(ctx.finding(
                            "OBJ_OVERLAPPING_SUBNET", vdom=vdom,
                            affected_object=f"{name_a} / {name_b}",
                            description=(f"'{inner[0]}' ({inner[1]}) sits inside "
                                         f"'{outer[0]}' ({outer[1]})."),
                            evidence=[obj_a.evidence_line(), obj_b.evidence_line()],
                            confidence=Confidence.MEDIUM))
        return out

    def _orphan_vips(self, ctx: AnalyzerContext, vdom: str) -> list[Finding]:
        if vdom != GLOBAL_VDOM and ctx.resolver.central_nat(vdom):
            return []
        out: list[Finding] = []
        cc = ctx.coverage_confidence_for(VIP)
        for section in ("firewall vip", "firewall vip6"):
            for obj in ctx.model.local_objects(section, vdom):
                if not obj.name or _is_used(ctx, ctx.resolver.used_vips, vdom, obj.name):
                    continue
                out.append(ctx.finding(
                    "OBJ_ORPHAN_VIP", vdom=vdom, affected_object=obj.name,
                    description=(f"VIP '{obj.name}' ({','.join(obj.get_list('extip')) or '?'} "
                                 f"to {','.join(obj.get_list('mappedip')) or '?'}) isn't used "
                                 f"by any rule or VIP group."),
                    evidence=[obj.evidence_line()],
                    confidence=Confidence.MEDIUM,
                    coverage_confidence=cc))
        return out
