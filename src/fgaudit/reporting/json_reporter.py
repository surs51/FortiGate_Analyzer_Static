from __future__ import annotations

import json

from .base import ReportContext, Reporter


class JsonReporter(Reporter):
    extension = "json"

    def render(self, ctx: ReportContext) -> str:
        payload = {
            "tool": ctx.meta.get("tool", "fgaudit"),
            "schema_version": "1.3",
            "metadata": ctx.meta,
            "coverage": ctx.meta.get("coverage"),
            "summary": ctx.summary.to_dict(),
            "findings": [
                f.to_dict()
                for f in sorted(ctx.findings, key=lambda x: (-x.risk_score, x.severity.value))
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)
