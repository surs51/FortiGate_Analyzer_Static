from __future__ import annotations

import csv
import io

from .base import ReportContext, Reporter, ip_ref_text

COLUMNS = [
    "unique_id", "rule_id", "vdom", "category", "severity", "confidence",
    "risk_score", "exposure", "affected_object", "title", "description",
    "impact", "recommendation", "references", "compliance", "evidence", "ips",
]


class CsvReporter(Reporter):
    extension = "csv"

    def render(self, ctx: ReportContext) -> str:
        buf = io.StringIO()
        columns = ["device"] + COLUMNS if ctx.meta.get("devices") else COLUMNS
        writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for f in sorted(ctx.findings, key=lambda x: (-x.risk_score, x.severity.value)):
            d = f.to_dict()
            d["references"] = " | ".join(d["references"])
            d["evidence"] = " | ".join(d["evidence"])
            d["ips"] = " | ".join(ip_ref_text(r) for r in f.ips)
            d["compliance"] = "; ".join(
                f"{fw}: {', '.join(ctrls)}" for fw, ctrls in d["compliance"].items()
            )
            writer.writerow(d)
        return buf.getvalue()
