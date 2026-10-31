from __future__ import annotations

import abc
import datetime as _dt
import logging
from typing import Any, Iterable, Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity
from ..knowledge import FosVersion, parse_version
from ..models import ConfigModel
from ..object_resolver import EffectivePolicy, ObjectResolver, SetResolver
from ..object_resolver.algebra import InterfaceSet
from ..rules import get_rule
from ..scoring import score_finding

logger = logging.getLogger(__name__)


class AnalyzerConfig:
    def __init__(
        self,
        excessive_policy_count: int = 300,
        max_group_depth: int = 4,
        short_retention_days: int = 30,
        long_admin_timeout: int = 15,
        shadow_scan_limit: int = 5000,
        today: Optional[_dt.date] = None,
    ) -> None:
        self.excessive_policy_count = excessive_policy_count
        self.max_group_depth = max_group_depth
        self.short_retention_days = short_retention_days
        self.long_admin_timeout = long_admin_timeout
        self.shadow_scan_limit = shadow_scan_limit
        self.today = today or _dt.date.today()


class AnalyzerContext:
    def __init__(
        self,
        model: ConfigModel,
        resolver: ObjectResolver,
        sets: Optional[SetResolver] = None,
        config: Optional[AnalyzerConfig] = None,
        coverage: "object | None" = None,
        meta: Optional[dict] = None,
        hit_counts: Optional[dict] = None,
        psirt_feed: Optional[dict] = None,
    ) -> None:
        self.model = model
        self.resolver = resolver
        self.sets = sets or resolver.sets
        self.config = config or AnalyzerConfig()
        self.coverage = coverage
        self.meta: dict = meta or {}
        self.hit_counts = hit_counts
        self.psirt_feed = psirt_feed
        self.artifacts: dict[str, Any] = {}

    @property
    def version(self) -> Optional[FosVersion]:
        return parse_version(self.meta.get("fortios_version"))

    @property
    def today(self) -> _dt.date:
        return self.config.today

    def effective(self, vdom: str) -> list[EffectivePolicy]:
        return self.sets.effective_policies(vdom)

    def wan_names(self) -> set[str]:
        return self.resolver.internet_facing_interfaces

    def is_wan_intf_set(self, names: InterfaceSet) -> bool:
        wan = self.wan_names()
        if names.is_any:
            return bool(wan)
        return bool(names.names & wan)

    def is_wan_name(self, name: str) -> bool:
        return name in self.wan_names()

    def exposure_for(self, ep: EffectivePolicy) -> Exposure:
        if self.is_wan_intf_set(ep.src_intf):
            return Exposure.INTERNET_FACING
        if ep.targets_vip:
            return Exposure.PUBLISHED_SERVICE
        return Exposure.INTERNAL

    def hits_for(self, vdom: str, policyid: str) -> Optional[int]:
        hc = self.hit_counts
        if hc is None:
            return None
        scoped = hc.get(vdom)
        val = scoped.get(policyid) if isinstance(scoped, dict) else hc.get(policyid)
        try:
            return int(val) if val is not None else None
        except (TypeError, ValueError):
            return None

    def coverage_confidence_for(self, *kinds: str) -> float:
        getter = getattr(self.coverage, "reference_confidence", None)
        return getter() if callable(getter) else 1.0

    def finding(
        self,
        rule_id: str,
        *,
        vdom: str,
        affected_object: str,
        description: str,
        evidence: Optional[Iterable[str]] = None,
        severity: Optional[Severity] = None,
        confidence: Confidence = Confidence.MEDIUM,
        exposure: Exposure = Exposure.INTERNAL,
        coverage_confidence: float = 1.0,
    ) -> Finding:
        meta = get_rule(rule_id)
        description = description[:1].upper() + description[1:]
        finding = Finding(
            rule_id=rule_id,
            vdom=vdom,
            category=meta.category,
            severity=severity or meta.severity,
            confidence=confidence,
            affected_object=affected_object,
            title=meta.title,
            description=description,
            impact=meta.impact,
            recommendation=meta.recommendation,
            references=list(meta.references),
            evidence=list(evidence or []),
            compliance={k: list(v) for k, v in meta.compliance.items()},
            exposure=exposure,
            coverage_confidence=coverage_confidence,
        )
        score_finding(finding)
        return finding


class Analyzer(abc.ABC):
    name: str = "analyzer"
    category: Category = Category.HARDENING

    @abc.abstractmethod
    def analyze(self, ctx: AnalyzerContext) -> list[Finding]:
        ...


_REGISTRY: list[type[Analyzer]] = []


def register(cls: type[Analyzer]) -> type[Analyzer]:
    _REGISTRY.append(cls)
    return cls


def get_analyzers() -> list[Analyzer]:
    return [cls() for cls in sorted(_REGISTRY, key=lambda c: c.name)]


def registered_names() -> list[str]:
    return sorted(c.name for c in _REGISTRY)


def join_names(names: Iterable[str], limit: int = 12) -> str:
    items = list(names)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def and_join(items: Iterable[str]) -> str:
    words = list(items)
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def plural(count: int, singular: str, plural_form: Optional[str] = None) -> str:
    word = singular if count == 1 else (plural_form or singular + "s")
    return f"{count} {word}"
