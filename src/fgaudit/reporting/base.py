from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..findings import Finding, IpRef
from ..scoring import Summary


@dataclass(slots=True)
class ReportContext:
    findings: list[Finding]
    summary: Summary
    meta: dict[str, Any] = field(default_factory=dict)


class Reporter(abc.ABC):
    extension: str = "txt"
    binary: bool = False

    @abc.abstractmethod
    def render(self, ctx: ReportContext) -> str | bytes:
        ...

    def write(self, ctx: ReportContext, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.render(ctx)
        if self.binary or isinstance(data, bytes):
            path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        else:
            path.write_text(data, encoding="utf-8")
        return path


def ip_ref_text(ref: IpRef) -> str:
    ips = ", ".join(ref.ips) or "no IP address"
    if ref.more:
        ips += f" and {ref.more} more"
    where = f"{ref.source}, line {ref.line}" if ref.line else ref.source
    note = f"; {ref.note}" if ref.note else ""
    return f"{ips} (from {where}: set {ref.setting} {ref.written}{note})"


def grouped_warnings(devices: list[dict]) -> list[tuple[str, list[str]]]:
    seen: dict[str, list[str]] = {}
    for d in devices:
        for w in (d.get("coverage") or {}).get("warnings", []):
            seen.setdefault(w, []).append(d["device"])
    return [(w, [] if len(names) == len(devices) else names) for w, names in seen.items()]


def score_band(score: int) -> tuple[str, str]:
    if score >= 85:
        return "A", "strong"
    if score >= 70:
        return "B", "good"
    if score >= 50:
        return "C", "fair"
    if score >= 30:
        return "D", "weak"
    return "F", "poor"
