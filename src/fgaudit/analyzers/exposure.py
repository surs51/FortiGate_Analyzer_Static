from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..findings import Category, Confidence, Exposure, Finding
from ..knowledge import is_public_address
from ..models import ConfigObject
from ..object_resolver import EffectivePolicy, VipInfo
from ..object_resolver.algebra import ipset_to_strings, service_to_strings
from .base import Analyzer, AnalyzerContext, register


@dataclass
class ExposureEntry:
    external: str
    internal: str
    service: str
    via: str
    policy_id: Optional[str]
    policy_label: Optional[str]
    vdom: str
    profiles: list[str] = field(default_factory=list)
    ssl_depth: Optional[str] = None
    naked: bool = False
    refs: tuple[ConfigObject, ...] = ()

    def to_dict(self) -> dict:
        return {
            "external": self.external,
            "internal": self.internal,
            "service": self.service,
            "via": self.via,
            "policy": self.policy_id,
            "profiles": self.profiles or ["none"],
            "ssl_inspection": self.ssl_depth or "n/a",
            "naked": self.naked,
        }


def _short_profile(key: str) -> str:
    for suffix in ("-profile", "-sensor", "-list"):
        if key.endswith(suffix):
            return key[: -len(suffix)]
    return key


@register
class ExposureAnalyzer(Analyzer):
    name = "exposure"
    category = Category.FIREWALL_POLICY

    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        findings: list[Finding] = []
        emap: dict[str, list[dict]] = ctx.artifacts.setdefault("exposure_map", {})

        for vdom in ctx.model.policy_vdoms:
            eff = [ep for ep in ctx.effective(vdom) if ep.enabled and not ep.matches_nothing()]
            central = ctx.resolver.central_nat(vdom)
            entries: list[ExposureEntry] = []
            covered: set[str] = set()

            for vip in ctx.sets.vips(vdom).values():
                if not vip.enabled:
                    continue
                permitting = self._permitting(ctx, eff, vip, central)
                if permitting:
                    for ep in permitting:
                        entries.append(self._vip_entry(ctx, vip, ep))
                        covered.add(ep.policyid)
                elif self._looks_public(ctx, vip):
                    entries.append(self._vip_entry(ctx, vip, None))

            for idx, ep in enumerate(eff):
                if not ep.is_allow or ep.targets_vip or ep.policyid in covered:
                    continue
                if not ctx.is_wan_intf_set(ep.src_intf):
                    continue
                if self._blocked_above(eff[:idx], ep):
                    continue
                entries.append(self._policy_entry(ctx, ep))

            if entries:
                emap[vdom] = [e.to_dict() for e in entries]
            for e in entries:
                finding = self._finding_for(ctx, e)
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def _blocked_above(above: list[EffectivePolicy], ep: EffectivePolicy) -> bool:
        return any(i.action == "deny" and i.fully_covers(ep) for i in above)

    def _permitting(self, ctx: AnalyzerContext, eff: list[EffectivePolicy],
                    vip: VipInfo, central: bool) -> list[EffectivePolicy]:
        out: list[EffectivePolicy] = []
        for idx, ep in enumerate(eff):
            if not ep.is_allow or not ctx.is_wan_intf_set(ep.src_intf):
                continue
            if vip.extintf != "any":
                listen_on = ctx.sets.zone_members(ep.vdom, vip.extintf) or [vip.extintf]
                if not any(ep.src_intf.contains(m) for m in listen_on):
                    continue
            if central:
                if ep.dst_ip.overlaps(vip.mapped) and not ep.targets_vip:
                    if not self._blocked_above(eff[:idx], ep):
                        out.append(ep)
                        break
            elif any(v.name == vip.name for v in ep.vips):
                if not self._blocked_above(eff[:idx], ep):
                    out.append(ep)
        return out

    @staticmethod
    def _looks_public(ctx: AnalyzerContext, vip: VipInfo) -> bool:
        if vip.extintf != "any" and ctx.is_wan_name(vip.extintf):
            return True
        return any(is_public_address(spec.split("-")[0])
                   for spec in vip.external_text.split(","))

    def _vip_entry(self, ctx: AnalyzerContext, vip: VipInfo,
                   ep: Optional[EffectivePolicy]) -> ExposureEntry:
        if ep is None:
            service = "no rule allows it"
            profiles: list[str] = []
        else:
            forwarded = vip.forwarded_service()
            svc = ep.service.intersection(forwarded) if forwarded else ep.service
            service = ", ".join(service_to_strings(svc))
            profiles = self._profile_list(ep)
        return ExposureEntry(
            external=vip.external_label(),
            internal=vip.mapped_label(),
            service=service,
            via=f"vip:{vip.name}",
            policy_id=ep.policyid if ep else None,
            policy_label=ep.label if ep else None,
            vdom=vip.vdom,
            profiles=profiles,
            ssl_depth=self._ssl_depth(ctx, ep),
            naked=ep is not None and not profiles,
            refs=(vip.obj,) + ((ep.policy,) if ep else ()),
        )

    def _policy_entry(self, ctx: AnalyzerContext, ep: EffectivePolicy) -> ExposureEntry:
        profiles = self._profile_list(ep)
        dst = ", ".join(ep.dst_display or ipset_to_strings(ep.dst_ip, limit=3))
        src = ", ".join(ep.src_display or ipset_to_strings(ep.src_ip, limit=3))
        return ExposureEntry(
            external=f"from {src}",
            internal=dst,
            service=", ".join(service_to_strings(ep.service)),
            via=f"policy:{ep.policyid}",
            policy_id=ep.policyid,
            policy_label=ep.label,
            vdom=ep.vdom,
            profiles=profiles,
            ssl_depth=self._ssl_depth(ctx, ep),
            naked=not profiles,
            refs=(ep.policy,),
        )

    @staticmethod
    def _profile_list(ep: EffectivePolicy) -> list[str]:
        return [f"{_short_profile(k)}:{v}" for k, v in ep.profile_map().items()]

    @staticmethod
    def _ssl_depth(ctx: AnalyzerContext, ep: Optional[EffectivePolicy]) -> Optional[str]:
        if ep is None or not ep.ssl_profile:
            return None
        return ctx.resolver.ssl_depth(ep.vdom, ep.ssl_profile)

    def _finding_for(self, ctx: AnalyzerContext, e: ExposureEntry) -> Optional[Finding]:
        if e.policy_id is None or not e.naked:
            return None
        if e.via.startswith("vip:"):
            what = (f"VIP {e.via[4:]} publishes {e.external} to {e.internal}, and "
                    f"{e.policy_label} lets the internet reach it ({e.service})")
        else:
            service = "any port" if e.service == "ALL" else e.service
            what = (f"{e.policy_label} lets internet traffic {e.external} reach "
                    f"{e.internal} on {service}")
        target = (f"VIP {e.via[4:]} via {e.policy_label}" if e.via.startswith("vip:")
                  else e.policy_label)
        return ctx.finding(
            "EXPOSURE_NAKED_SERVICE",
            vdom=e.vdom,
            affected_object=target,
            description=f"{what}. The rule has no security profile, so nothing inspects "
                        f"that traffic.",
            evidence=[r.evidence_line() for r in e.refs]
                     + [f"external: {e.external}", f"internal: {e.internal}",
                      f"service: {e.service}", f"allowed by: {e.policy_label}",
                      "security profiles: none",
                      f"SSL inspection: {e.ssl_depth or 'n/a'}"],
            confidence=Confidence.MEDIUM,
            exposure=Exposure.INTERNET_FACING,
        )
