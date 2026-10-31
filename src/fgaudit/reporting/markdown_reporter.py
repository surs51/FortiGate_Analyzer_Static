from __future__ import annotations

from ..findings import Finding, Severity
from .base import ReportContext, Reporter, grouped_warnings, ip_ref_text, score_band

_SEV_ORDER = [s.label for s in Severity]


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _exposure_tables(emap: dict, heading: str) -> list[str]:
    lines: list[str] = []
    for vdom, entries in emap.items():
        if not entries:
            continue
        lines.append(f"{heading} VDOM `{vdom}`\n")
        lines.append("| Reachable at | Lands on | Service | Allowed by | Inspection | SSL |")
        lines.append("|---|---|---|---|---|---|")
        for e in entries:
            via = e["via"].replace("vip:", "VIP ").replace("policy:", "rule ")
            allowed = f"rule {e['policy']}" if e.get("policy") else "no rule"
            if e["via"].startswith("vip:"):
                allowed += f" via {via}"
            inspection = ("**none**" if e["naked"]
                          else ", ".join(e["profiles"]))
            lines.append(f"| {_cell(e['external'])} | {_cell(e['internal'])} | "
                         f"{_cell(e['service'])} | {_cell(allowed)} | "
                         f"{_cell(inspection)} | {_cell(e['ssl_inspection'])} |")
        lines.append("")
    return lines


def _nat_line(nat: dict) -> str:
    modes = ", ".join(f"{k}: `{v}`" for k, v in nat.items())
    return (f"**NAT mode** ({modes}). In central NAT mode the per-rule NAT "
            f"setting does nothing and source NAT comes from the central SNAT "
            f"table.\n")


class MarkdownReporter(Reporter):
    extension = "md"

    def render(self, ctx: ReportContext) -> str:
        s = ctx.summary
        meta = ctx.meta
        devices = meta.get("devices") or []
        lines: list[str] = []
        grade, word = score_band(s.overall_score)

        lines.append("# FortiGate configuration review\n")
        if devices:
            lines.append(f"**Folder:** `{meta.get('source_file', 'n/a')}` · "
                         f"**Devices:** {len(devices)} · "
                         f"**Rules:** {meta.get('policy_count', '?')} · "
                         f"**Reviewed:** {meta.get('generated_at', '')}\n")
        else:
            lines.append(f"**Device:** {meta.get('platform') or 'unknown model'}, FortiOS "
                         f"{meta.get('fortios_version') or 'unknown'} (build {meta.get('build') or '?'})  ")
            lines.append(f"**File:** `{meta.get('source_file', 'n/a')}` · "
                         f"**VDOMs:** {', '.join(meta.get('vdoms', []) or ['root'])} · "
                         f"**Rules:** {meta.get('policy_count', '?')} · "
                         f"**Reviewed:** {meta.get('generated_at', '')}\n")

        lines.append("## Summary\n")
        sev = s.by_severity
        internet = s.by_exposure.get("internet-facing", 0)
        counts = (f"{sev.get('Critical', 0)} critical, {sev.get('High', 0)} high, "
                  f"{sev.get('Medium', 0)} medium, {sev.get('Low', 0)} low "
                  f"and {sev.get('Informational', 0)} informational. {internet} of them involve "
                  f"traffic from the internet.")
        if devices:
            weakest = min(s.by_device, key=lambda d: s.by_device[d]["overall_score"])
            lines.append(
                f"The review found {s.total_findings} issues across {len(devices)} devices: "
                f"{counts} The lowest device score is **{s.overall_score}/100** "
                f"(grade {grade}, {word}), on `{weakest}`.\n")
            lines.extend(self._devices_md(ctx))
        else:
            lines.append(
                f"The review found {s.total_findings} issues: {counts} Overall score: "
                f"**{s.overall_score}/100** (grade {grade}, {word}).\n")

        if s.top_risks:
            lines.append("### Fix these first\n")
            for t in s.top_risks:
                where = f"{t['device']}, VDOM {t['vdom']}" if t.get("device") else f"VDOM {t['vdom']}"
                lines.append(f"- **{t['severity']}**: {t['title']} (`{t['affected_object']}`, "
                             f"{where}, risk {t['risk_score']})")
            lines.append("")

        if devices:
            lines.extend(self._fleet_exposure_md(devices))
        else:
            emap = meta.get("exposure_map") or {}
            if any(emap.values()):
                lines.append("## What the internet can reach\n")
                wan = meta.get("internet_facing_interfaces") or []
                if wan:
                    lines.append(f"Internet-facing interfaces: {', '.join(wan)}.\n")
                lines.append("Published servers (VIPs) and rules that let internet traffic in, "
                             "with the inspection on each path.\n")
                lines.extend(_exposure_tables(emap, "###"))

            nat = meta.get("nat_mode") or {}
            if nat:
                lines.append(_nat_line(nat))

        if s.remediation:
            lines.append("## What to fix, in order\n")
            for i, r in enumerate(s.remediation[:15], 1):
                count = f" ({r['count']} findings)" if r["count"] > 1 else ""
                if len(r.get("devices", [])) > 1:
                    count = f" ({r['count']} findings on {len(r['devices'])} devices)"
                lines.append(f"{i}. **{r['title']}** ({r['severity'].lower()}){count}. "
                             f"{r['recommendation']}")
            lines.append("")

        lines.append("## Findings\n")
        groups: dict[str, list[Finding]] = {k: [] for k in _SEV_ORDER}
        for f in ctx.findings:
            groups[f.severity.label].append(f)
        for label in _SEV_ORDER:
            items = sorted(groups[label], key=lambda f: -f.risk_score)
            if not items:
                continue
            lines.append(f"### {label} ({len(items)})\n")
            for f in items:
                lines.append(self._finding_md(f))

        if devices:
            lines.extend(self._fleet_coverage_md(devices))
        else:
            cov = meta.get("coverage") or {}
            if cov:
                sc = cov.get("summary", {})
                lines.append("## What this review covered\n")
                lines.append(f"{sc.get('analyzed', 0)} areas were checked, "
                             f"{sc.get('references_only', 0)} were read only to see which objects "
                             f"are in use, and {sc.get('not_modeled', 0)} were present but not read.\n")
                for w in cov.get("warnings", []):
                    lines.append(f"- {w}")
                lines.append("")

        lines.append("---")
        lines.append(f"_Made by fgaudit {meta.get('tool_version', '')}. This is an offline "
                     f"review of a configuration file; nothing was scanned or tested on the "
                     f"device. Check each finding against how the network is really used "
                     f"before you change anything._")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _devices_md(ctx: ReportContext) -> list[str]:
        by_device = ctx.summary.by_device
        lines = ["## Devices\n",
                 "| Device | Hostname | Model | FortiOS | VDOMs | Rules | Findings | Critical "
                 "| High | Score |",
                 "|---|---|---|---|---|---|---|---|---|---|"]
        for d in ctx.meta["devices"]:
            ds = by_device.get(d["device"], {})
            sev = ds.get("by_severity", {})
            score = ds.get("overall_score", 100)
            grade, _ = score_band(score)
            lines.append(
                f"| `{_cell(d['device'])}` | {_cell(d.get('hostname') or '')} | "
                f"{_cell(d.get('platform') or 'unknown')} | "
                f"{_cell(d.get('fortios_version') or 'unknown')} | "
                f"{_cell(', '.join(d.get('vdoms') or ['root']))} | {d.get('policy_count', 0)} | "
                f"{ds.get('total_findings', 0)} | {sev.get('Critical', 0)} | "
                f"{sev.get('High', 0)} | {score} ({grade}) |")
        lines.append("")
        skipped = ctx.meta.get("skipped_files") or []
        if skipped:
            lines.append("These files were skipped and are not in this report:\n")
            lines.extend(f"- `{sk['file']}`: {sk['reason']}" for sk in skipped)
            lines.append("")
        return lines

    @staticmethod
    def _fleet_exposure_md(devices: list[dict]) -> list[str]:
        shown = [d for d in devices
                 if any((d.get("exposure_map") or {}).values()) or d.get("nat_mode")]
        if not shown:
            return []
        lines = ["## What the internet can reach\n",
                 "Published servers (VIPs) and rules that let internet traffic in, "
                 "with the inspection on each path.\n"]
        for d in shown:
            lines.append(f"### `{d['device']}`\n")
            wan = d.get("internet_facing_interfaces") or []
            if wan:
                lines.append(f"Internet-facing interfaces: {', '.join(wan)}.\n")
            if d.get("nat_mode"):
                lines.append(_nat_line(d["nat_mode"]))
            lines.extend(_exposure_tables(d.get("exposure_map") or {}, "####"))
        return lines

    @staticmethod
    def _fleet_coverage_md(devices: list[dict]) -> list[str]:
        lines = ["## What this review covered\n"]
        for d in devices:
            sc = (d.get("coverage") or {}).get("summary", {})
            lines.append(f"- `{d['device']}`: {sc.get('analyzed', 0)} areas checked, "
                         f"{sc.get('references_only', 0)} read only for references, "
                         f"{sc.get('not_modeled', 0)} present but not read.")
        lines.append("")
        for w, names in grouped_warnings(devices):
            suffix = f" ({', '.join(names)})" if names else ""
            lines.append(f"- {w}{suffix}")
        lines.append("")
        return lines

    @staticmethod
    def _finding_md(f: Finding) -> str:
        b: list[str] = [f"#### {f.title}", ""]
        device = f"device `{f.device}` · " if f.device else ""
        b.append(f"`{f.rule_id}` · risk {f.risk_score}/100 · confidence {f.confidence.value} · "
                 f"{f.exposure.value} · {device}VDOM {f.vdom} · `{f.affected_object}`")
        b.append("")
        b.append(f"**What we found:** {f.description}  ")
        b.append(f"**Why it matters:** {f.impact}  ")
        b.append(f"**How to fix:** {f.recommendation}")
        if f.evidence:
            b.append("")
            b.append("Evidence from the config:")
            b.append("")
            b.extend(f"- `{e}`" for e in f.evidence)
        if f.ips:
            b.append("")
            b.append("IP addresses from the config:")
            b.append("")
            b.extend(f"- {ip_ref_text(r)}" for r in f.ips)
        if f.compliance:
            b.append("")
            b.append("Related controls: " + "; ".join(
                f"{k} {', '.join(v)}" for k, v in f.compliance.items()))
        b.append("")
        return "\n".join(b)
