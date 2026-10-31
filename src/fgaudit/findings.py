from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFORMATIONAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def base_score(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFORMATIONAL: 1,
        }[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


class Confidence(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def factor(self) -> float:
        return {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.85, Confidence.LOW: 0.6}[self]


class Exposure(enum.Enum):
    INTERNET_FACING = "internet-facing"
    MANAGEMENT_PLANE = "management plane"
    PUBLISHED_SERVICE = "published services"
    INTERNAL = "internal"

    @property
    def multiplier(self) -> float:
        return {
            Exposure.INTERNET_FACING: 1.5,
            Exposure.MANAGEMENT_PLANE: 1.4,
            Exposure.PUBLISHED_SERVICE: 1.3,
            Exposure.INTERNAL: 1.0,
        }[self]


class Category(str, enum.Enum):
    FIREWALL_POLICY = "Firewall Policy"
    OBJECTS = "Objects"
    ADMIN = "Administrative Security"
    AUTH = "Authentication"
    INTERFACE = "Interface"
    VPN = "VPN"
    SECURITY_PROFILE = "Security Profile"
    LOGGING = "Logging & Monitoring"
    HIGH_AVAILABILITY = "High Availability"
    HARDENING = "System Hardening"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class IpRef:
    source: str
    setting: str
    written: str
    ips: tuple[str, ...]
    line: int = 0
    more: int = 0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source": self.source,
            "line": self.line,
            "setting": self.setting,
            "written": self.written,
            "ips": list(self.ips),
        }
        if self.more:
            out["more"] = self.more
        if self.note:
            out["note"] = self.note
        return out


def _finding_id(rule_id: str, vdom: str, affected_object: str, device: str = "") -> str:
    parts = (device, rule_id, vdom, affected_object) if device else (rule_id, vdom, affected_object)
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return f"{rule_id}-{digest[:8]}"


@dataclass(slots=True)
class Finding:
    rule_id: str
    vdom: str
    category: Category
    severity: Severity
    confidence: Confidence
    affected_object: str
    title: str
    description: str
    impact: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    compliance: dict[str, list[str]] = field(default_factory=dict)
    exposure: Exposure = Exposure.INTERNAL
    coverage_confidence: float = 1.0
    risk_score: int = 0
    unique_id: str = ""
    device: str = ""
    ips: list[IpRef] = field(default_factory=list)

    @property
    def detection_confidence(self) -> Confidence:
        return self.confidence

    @property
    def effective_confidence(self) -> float:
        return self.confidence.factor * max(0.0, min(1.0, self.coverage_confidence))

    def __post_init__(self) -> None:
        if not self.unique_id:
            self.unique_id = _finding_id(self.rule_id, self.vdom, self.affected_object,
                                         self.device)

    def assign_device(self, device: str) -> None:
        self.device = device
        self.unique_id = _finding_id(self.rule_id, self.vdom, self.affected_object, device)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"unique_id": self.unique_id}
        if self.device:
            out["device"] = self.device
        out.update({
            "rule_id": self.rule_id,
            "vdom": self.vdom,
            "category": str(self.category),
            "severity": self.severity.label,
            "confidence": self.confidence.value,
            "detection_confidence": self.confidence.value,
            "coverage_confidence": round(self.coverage_confidence, 3),
            "effective_confidence": round(self.effective_confidence, 3),
            "risk_score": self.risk_score,
            "exposure": self.exposure.value,
            "affected_object": self.affected_object,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "references": list(self.references),
            "evidence": list(self.evidence),
            "ips": [r.to_dict() for r in self.ips],
            "compliance": {k: list(v) for k, v in self.compliance.items()},
        })
        return out
