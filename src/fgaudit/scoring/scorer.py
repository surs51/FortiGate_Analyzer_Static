from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..findings import Category, Confidence, Exposure, Finding, Severity

_RETENTION = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.985,
    Severity.MEDIUM: 0.998,
    Severity.LOW: 0.9995,
    Severity.INFORMATIONAL: 1.0,
}
_FLOOR = 1
_CAPS = {Severity.CRITICAL: 49, Severity.HIGH: 79}


def score_finding(finding: Finding) -> int:
    raw = (
        finding.severity.base_score
        * finding.confidence.factor
        * max(0.0, min(1.0, finding.coverage_confidence))
        * finding.exposure.multiplier
    )
    finding.risk_score = max(0, min(100, round(raw)))
    return finding.risk_score


def overall_score(findings: Iterable[Finding]) -> int:
    score = 100.0
    cap = 100
    for f in findings:
        score *= _RETENTION[f.severity]
        if f.confidence is not Confidence.LOW:
            cap = min(cap, _CAPS.get(f.severity, 100))
    return max(_FLOOR, min(cap, round(score)))


@dataclass(slots=True)
class Summary:
    overall_score: int
    total_findings: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_vdom: dict[str, int]
    by_exposure: dict[str, int]
    heatmap: dict[str, dict[str, int]]
    top_risks: list[dict]
    remediation: list[dict]
    compliance_hits: dict[str, int]
    by_device: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "overall_score": self.overall_score,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "by_vdom": self.by_vdom,
            "by_exposure": self.by_exposure,
            "heatmap": self.heatmap,
            "top_risks": self.top_risks,
            "remediation": self.remediation,
            "compliance_hits": self.compliance_hits,
        }
        if self.by_device:
            out["by_device"] = self.by_device
        return out


def _device_summary(findings: list[Finding]) -> dict:
    by_sev = Counter(f.severity.label for f in findings)
    return {
        "overall_score": overall_score(findings),
        "total_findings": len(findings),
        "by_severity": {s.label: by_sev.get(s.label, 0) for s in Severity},
    }


def build_summary(findings: list[Finding], devices: Optional[Iterable[str]] = None) -> Summary:
    for f in findings:
        if not f.risk_score:
            score_finding(f)

    by_sev = Counter(f.severity.label for f in findings)
    by_cat = Counter(str(f.category) for f in findings)
    by_vdom = Counter(f.vdom for f in findings)
    by_exp = Counter(f.exposure.value for f in findings)

    heatmap: dict[str, dict[str, int]] = {
        str(c): {s.label: 0 for s in Severity} for c in Category
    }
    for f in findings:
        heatmap[str(f.category)][f.severity.label] += 1

    ranked = sorted(
        findings,
        key=lambda f: (
            -f.risk_score,
            0 if f.exposure is Exposure.INTERNET_FACING else 1,
            f.severity.value,
        ),
    )
    top_risks = []
    for f in ranked[:10]:
        entry = {
            "unique_id": f.unique_id,
            "title": f.title,
            "severity": f.severity.label,
            "risk_score": f.risk_score,
            "vdom": f.vdom,
            "affected_object": f.affected_object,
            "exposure": f.exposure.value,
        }
        if f.device:
            entry["device"] = f.device
        top_risks.append(entry)

    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule_id].append(f)
    roadmap = []
    for rule_id, items in groups.items():
        worst = min(items, key=lambda f: f.severity.value)
        entry = {
            "rule_id": rule_id,
            "title": worst.title,
            "severity": worst.severity.label,
            "count": len(items),
            "max_risk_score": max(i.risk_score for i in items),
            "recommendation": worst.recommendation,
            "category": str(worst.category),
        }
        if devices is not None:
            entry["devices"] = sorted({i.device for i in items})
        roadmap.append(entry)
    roadmap.sort(
        key=lambda r: (Severity.from_str(r["severity"]).value, -r["max_risk_score"], -r["count"])
    )

    compliance_hits: Counter[str] = Counter()
    for f in findings:
        for fw in f.compliance:
            compliance_hits[fw] += 1

    ordered_by_sev = {s.label: by_sev.get(s.label, 0) for s in Severity}

    by_device: dict[str, dict] = {}
    if devices is not None:
        for name in devices:
            by_device[name] = _device_summary([f for f in findings if f.device == name])
    if by_device:
        score = min(d["overall_score"] for d in by_device.values())
    else:
        score = overall_score(findings)

    return Summary(
        overall_score=score,
        total_findings=len(findings),
        by_severity=ordered_by_sev,
        by_category=dict(by_cat),
        by_vdom=dict(by_vdom),
        by_exposure=dict(by_exp),
        heatmap=heatmap,
        top_risks=top_risks,
        remediation=roadmap,
        compliance_hits=dict(compliance_hits),
        by_device=by_device,
    )
