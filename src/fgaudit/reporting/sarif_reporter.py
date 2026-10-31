from __future__ import annotations

import json
import re

from ..rules import get_rule
from .base import ReportContext, Reporter

_LINE_RE = re.compile(r"line\s+(\d+)")

_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "none",
}
_SECURITY_SEVERITY = {
    "Critical": "9.5",
    "High": "8.0",
    "Medium": "5.5",
    "Low": "3.0",
    "Informational": "1.0",
}


def _start_line(evidence: list[str]) -> int | None:
    for ev in evidence:
        m = _LINE_RE.search(ev)
        if m:
            return int(m.group(1))
    return None


class SarifReporter(Reporter):
    extension = "sarif"

    def render(self, ctx: ReportContext) -> str:
        rule_ids: list[str] = []
        for f in ctx.findings:
            if f.rule_id not in rule_ids:
                rule_ids.append(f.rule_id)
        rule_index = {rid: i for i, rid in enumerate(rule_ids)}

        rules = []
        for rid in rule_ids:
            meta = get_rule(rid)
            rule = {
                "id": rid,
                "name": "".join(p.capitalize() for p in rid.lower().split("_")),
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.impact},
                "help": {"text": meta.recommendation},
                "defaultConfiguration": {"level": _LEVEL.get(meta.severity.label, "warning")},
                "properties": {
                    "category": str(meta.category),
                    "security-severity": _SECURITY_SEVERITY.get(meta.severity.label, "5.5"),
                    "tags": ["security", "fortios", str(meta.category)] + list(meta.compliance),
                },
            }
            links = [r for r in meta.references if r.startswith("http")]
            if links:
                rule["helpUri"] = links[0]
            rules.append(rule)

        artifact_uri = ctx.meta.get("source_file", "fortigate.conf")
        results = []
        for f in ctx.findings:
            uri = f.device or artifact_uri
            where = f"{f.device} / {f.vdom}" if f.device else f.vdom
            location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            line = _start_line(f.evidence)
            if line is not None:
                location["physicalLocation"]["region"] = {"startLine": line}
            props = {
                "risk_score": f.risk_score,
                "confidence": f.confidence.value,
                "exposure": f.exposure.value,
                "vdom": f.vdom,
                "affected_object": f.affected_object,
            }
            if f.ips:
                props["ips"] = [r.to_dict() for r in f.ips]
            if f.device:
                props["device"] = f.device
            results.append({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _LEVEL.get(f.severity.label, "warning"),
                "message": {"text": f"[{where}] {f.description}"},
                "locations": [location],
                "partialFingerprints": {"fgauditId": f.unique_id},
                "properties": props,
            })

        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": ctx.meta.get("tool", "fgaudit"),
                        "version": ctx.meta.get("tool_version", "unknown"),
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
        return json.dumps(doc, indent=2, ensure_ascii=False)
