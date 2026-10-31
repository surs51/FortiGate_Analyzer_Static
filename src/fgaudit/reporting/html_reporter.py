from __future__ import annotations

import html
import json
import math

from ..findings import Category, Confidence, Exposure, IpRef, Severity
from .base import ReportContext, Reporter, grouped_warnings, score_band

SEV_ORDER = [s.label for s in Severity]
CAT_ORDER = [str(c) for c in Category]

SEV_COLOR = {
    "Critical": "#ff5c6c",
    "High": "#ff9f43",
    "Medium": "#ffd24c",
    "Low": "#4cc9f0",
    "Informational": "#8b93a8",
}
_GRADE_COLOR = {"A": "#3ddc97", "B": "#9ad13f", "C": "#ffd24c", "D": "#ff9f43", "F": "#ff5c6c"}


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _gauge_svg(score: int) -> str:
    grade, word = score_band(score)
    color = _GRADE_COLOR[grade]
    cx, cy, r = 130, 130, 100
    arc_len = math.pi * r
    filled = arc_len * (score / 100.0)
    path = f"M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}"
    return f"""<svg viewBox="0 0 260 165" class="gauge" role="img" aria-label="Score {score} out of 100">
  <path d="{path}" fill="none" stroke="#222a3d" stroke-width="18" stroke-linecap="round"/>
  <path d="{path}" fill="none" stroke="{color}" stroke-width="18" stroke-linecap="round" stroke-dasharray="{filled:.2f} {arc_len:.2f}"/>
  <text x="130" y="118" text-anchor="middle" class="gauge-score" fill="{color}">{score}</text>
  <text x="130" y="142" text-anchor="middle" class="gauge-sub">out of 100 &middot; grade {grade}</text>
  <text x="130" y="160" text-anchor="middle" class="gauge-word" fill="{color}">{word.upper()}</text>
</svg>"""


def _donut_svg(by_severity: dict[str, int]) -> str:
    total = sum(by_severity.values())
    r = 54
    c = 2 * math.pi * r
    if total == 0:
        segments = f'<circle cx="70" cy="70" r="{r}" fill="none" stroke="#222a3d" stroke-width="20"/>'
    else:
        parts = []
        done = 0.0
        for sev in SEV_ORDER:
            count = by_severity.get(sev, 0)
            if not count:
                continue
            seg = c * (count / total)
            parts.append(
                f'<circle cx="70" cy="70" r="{r}" fill="none" stroke="{SEV_COLOR[sev]}" '
                f'stroke-width="20" stroke-dasharray="{seg:.2f} {c - seg:.2f}" '
                f'stroke-dashoffset="{-done:.2f}"/>')
            done += seg
        segments = "".join(parts)
    return f"""<svg viewBox="0 0 140 140" class="donut" role="img" aria-label="Findings by severity">
  <g transform="rotate(-90 70 70)">{segments}</g>
  <text x="70" y="66" text-anchor="middle" class="donut-total">{total}</text>
  <text x="70" y="84" text-anchor="middle" class="donut-label">findings</text>
</svg>"""


def _legend(by_severity: dict[str, int]) -> str:
    rows = "".join(
        f'<li><span class="dot" style="background:{SEV_COLOR[sev]}"></span>'
        f'<span class="lg-label">{_esc(sev)}</span>'
        f'<span class="lg-count">{by_severity.get(sev, 0)}</span></li>'
        for sev in SEV_ORDER)
    return f'<ul class="legend">{rows}</ul>'


def _bars(items: list[tuple[str, int]], css: str = "") -> str:
    items = [(k, n) for k, n in items if n > 0]
    if not items:
        return '<p class="empty">Nothing to show.</p>'
    mx = max(n for _, n in items)
    rows = "".join(
        f'<div class="bar-row"><span class="bar-label">{_esc(k)}</span>'
        f'<span class="bar-track"><span class="bar-fill {css}" style="width:{n / mx * 100:.1f}%"></span></span>'
        f'<span class="bar-num">{n}</span></div>'
        for k, n in sorted(items, key=lambda x: -x[1]))
    return f'<div class="bars">{rows}</div>'


_COV_CLASS = {"analyzed": "cov-ok", "references-only": "cov-ref",
              "not-modeled": "cov-bad", "absent": "cov-absent"}
_COV_LABEL = {"analyzed": "Checked", "references-only": "Read for references",
              "not-modeled": "Not read", "absent": "Not in backup"}


def _warn_box(items: list[str]) -> str:
    if not items:
        return ""
    return f'<div class="cov-warn"><b>Good to know</b><ul>{"".join(items)}</ul></div>'


def _fleet_coverage_panel(devices: list[dict]) -> str:
    rows = []
    for d in devices:
        sc = (d.get("coverage") or {}).get("summary", {})
        rows.append(
            f'<tr><td class="cov-dom">{_esc(d["device"])}</td>'
            f'<td><span class="cov-badge cov-ok">{sc.get("analyzed", 0)}</span></td>'
            f'<td><span class="cov-badge cov-ref">{sc.get("references_only", 0)}</span></td>'
            f'<td><span class="cov-badge {"cov-bad" if sc.get("not_modeled") else "cov-absent"}">'
            f'{sc.get("not_modeled", 0)}</span></td></tr>')
    warns = []
    for w, names in grouped_warnings(devices):
        who = f' <span class="cov-who">{_esc(", ".join(names))}</span>' if names else ""
        warns.append(f"<li>{_esc(w)}{who}</li>")
    return f"""
  <section class="panel" id="coverage-section">
    <p class="sec-title">What this review covered</p>
    <p class="lead">How many areas of each backup were checked, read only to see which objects
      are in use, or present but not read. Notes that apply to only some devices name them.</p>
    <div class="scroll"><table class="cov-table">
      <thead><tr><th>Device</th><th>Checked</th><th>Read for references</th><th>Not read</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>
    {_warn_box(warns)}
  </section>"""


def _coverage_panel(meta: dict) -> str:
    if meta.get("devices"):
        return _fleet_coverage_panel(meta["devices"])
    cov = meta.get("coverage")
    if not cov:
        return ""
    rows = []
    for d in cov.get("domains", []):
        status = d.get("status", "absent")
        count = f'<span class="cov-count">{d.get("count", 0)}</span>' if d.get("present") else ""
        rows.append(
            f'<tr><td class="cov-dom">{_esc(d.get("domain", ""))}{count}</td>'
            f'<td><span class="cov-badge {_COV_CLASS.get(status, "cov-absent")}">'
            f'{_COV_LABEL.get(status, status)}</span></td>'
            f'<td class="cov-note">{_esc(d.get("note", ""))}</td></tr>')
    sc = cov.get("summary", {})
    notes = _warn_box([f"<li>{_esc(w)}</li>" for w in cov.get("warnings", [])])
    return f"""
  <section class="panel" id="coverage-section">
    <p class="sec-title">What this review covered</p>
    <p class="lead"><b>{sc.get('analyzed', 0)}</b> areas were checked,
      <b>{sc.get('references_only', 0)}</b> were read only to see which objects are in use, and
      <b>{sc.get('not_modeled', 0)}</b> were present but not read.</p>
    <table class="cov-table">
      <thead><tr><th>Area</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    {notes}
  </section>"""


_EXPOSURE_OPEN_LIMIT = 100
_NOTHING_REACHABLE = '<p class="empty">Nothing is reachable from the internet.</p>'


def _exposure_intro(meta: dict) -> str:
    nat = meta.get("nat_mode") or {}
    wan = meta.get("internet_facing_interfaces") or []
    intro = []
    if wan:
        intro.append(f'Internet-facing interfaces: <b>{_esc(", ".join(wan))}</b>.')
    if nat:
        modes = ", ".join(f"{_esc(k)}: <b>{_esc(v)}</b>" for k, v in nat.items())
        intro.append(f"NAT mode ({modes}). In central NAT mode the per-rule NAT setting does "
                     f"nothing and source NAT comes from the central SNAT table.")
    return f'<p class="natmode">{" ".join(intro)}</p>'


def _exposure_panel(meta: dict) -> str:
    devices = meta.get("devices")
    shown = [d for d in (devices or [meta])
             if any((d.get("exposure_map") or {}).values()) or d.get("nat_mode")]
    if not shown:
        return ""

    parts = []
    total_paths = sum(len(v) for d in shown for v in (d.get("exposure_map") or {}).values())
    for d in shown:
        tables = _exposure_tables(d.get("exposure_map") or {}) or _NOTHING_REACHABLE
        if not devices:
            parts.append(_exposure_intro(d) + tables)
            continue
        paths = sum(len(v) for v in (d.get("exposure_map") or {}).values())
        is_open = " open" if total_paths <= _EXPOSURE_OPEN_LIMIT else ""
        parts.append(f'<details class="exp-box"{is_open}><summary><p class="exp-dev">'
                     f'{_esc(d["device"])} <span class="muted">({paths} '
                     f'{"path" if paths == 1 else "paths"})</span></p></summary>'
                     f'{_exposure_intro(d)}{tables}</details>')
    body = "".join(parts)
    return f"""
  <section class="panel" id="exposure-section">
    <p class="sec-title">What the internet can reach</p>
    <p class="lead">Published servers (VIPs) and rules that let internet traffic in, with the
      inspection on each path. Paths blocked by an earlier deny rule are left out.</p>
    {body}
  </section>"""


def _exposure_tables(emap: dict) -> str:
    blocks = []
    for vdom, entries in emap.items():
        if not entries:
            continue
        rows = []
        for e in entries:
            allowed = f"rule {e['policy']}" if e.get("policy") else "no rule"
            if e["via"].startswith("vip:"):
                allowed += f" via VIP {e['via'][4:]}"
            inspection = ('<span class="exp-none">none</span>' if e.get("naked")
                          else _esc(", ".join(e.get("profiles", []))))
            rows.append(
                f'<tr><td>{_esc(e.get("external", ""))}</td>'
                f'<td>{_esc(e.get("internal", ""))}</td>'
                f'<td>{_esc(e.get("service", ""))}</td>'
                f'<td>{_esc(allowed)}</td>'
                f'<td class="exp-prof">{inspection}</td>'
                f'<td>{_esc(e.get("ssl_inspection", "n/a"))}</td></tr>')
        blocks.append(
            f'<p class="exp-vdom">VDOM {_esc(vdom)}</p>'
            f'<div class="scroll"><table class="exp-table"><thead><tr>'
            f'<th>Reachable at</th><th>Lands on</th><th>Service</th><th>Allowed by</th>'
            f'<th>Inspection</th><th>SSL</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')
    return "".join(blocks)


def _heatmap(heatmap: dict[str, dict[str, int]]) -> str:
    active = [c for c in CAT_ORDER if c in heatmap and sum(heatmap[c].values()) > 0]
    if not active:
        return '<p class="empty">Nothing to show.</p>'
    max_cell = max(heatmap[c][s] for c in active for s in SEV_ORDER) or 1
    head = "".join(f'<th class="hm-sev">{_esc(s)}</th>' for s in SEV_ORDER)
    body = []
    for cat in active:
        cells = []
        for sev in SEV_ORDER:
            n = heatmap[cat].get(sev, 0)
            if n == 0:
                cells.append('<td class="hm-cell hm-empty">&middot;</td>')
            else:
                op = 0.18 + 0.82 * (n / max_cell)
                cells.append(
                    f'<td class="hm-cell" data-cat="{_esc(cat)}" data-sev="{_esc(sev)}" '
                    f'style="background:{SEV_COLOR[sev]};opacity:{op:.2f}" '
                    f'title="{_esc(cat)}, {_esc(sev).lower()}: {n}">{n}</td>')
        body.append(f'<tr><th class="hm-cat">{_esc(cat)}</th>{"".join(cells)}</tr>')
    return (f'<div class="scroll"><table class="heatmap"><thead><tr><th class="hm-corner">'
            f'</th>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>')


def _stat_cards(ctx: ReportContext) -> str:
    s = ctx.summary
    internet = s.by_exposure.get("internet-facing", 0)
    mgmt = s.by_exposure.get("management plane", 0)
    cards = [
        ("Findings", s.total_findings, ""),
        ("Critical", s.by_severity.get("Critical", 0), "crit"),
        ("High", s.by_severity.get("High", 0), "high"),
        ("From the internet", internet, "crit" if internet else ""),
        ("Management", mgmt, "high" if mgmt else ""),
        ("Devices", len(ctx.meta["devices"]), "") if ctx.meta.get("devices")
        else ("VDOMs", len(ctx.meta.get("vdoms", []) or [1]), ""),
    ]
    out = "".join(
        f'<div class="stat {cls}"><div class="stat-val">{val}</div>'
        f'<div class="stat-label">{_esc(label)}</div></div>'
        for label, val, cls in cards)
    return f'<div class="stat-grid">{out}</div>'


def _top_risks(ctx: ReportContext) -> str:
    rows = []
    for r in ctx.summary.top_risks:
        color = SEV_COLOR.get(r["severity"], "#888")
        device = f'{_esc(r["device"])} &middot; ' if r.get("device") else ""
        rows.append(
            f'<li class="risk-item"><span class="risk-score" style="--c:{color}">{r["risk_score"]}</span>'
            f'<span class="risk-body"><span class="risk-title">{_esc(r["title"])}</span>'
            f'<span class="risk-meta">{device}{_esc(r["affected_object"])} &middot; VDOM {_esc(r["vdom"])}'
            f' &middot; {_esc(r["exposure"])}</span></span>'
            f'<span class="chip" style="--c:{color}">{_esc(r["severity"])}</span></li>')
    if not rows:
        return '<p class="empty">Nothing found.</p>'
    return f'<ol class="risk-list">{"".join(rows)}</ol>'


def _remediation(ctx: ReportContext) -> str:
    rows = []
    for i, r in enumerate(ctx.summary.remediation[:25], 1):
        color = SEV_COLOR.get(r["severity"], "#888")
        count = f' <span class="rem-count">&times;{r["count"]}</span>' if r["count"] > 1 else ""
        on = r.get("devices", [])
        if len(on) > 1:
            count += f' <span class="rem-count">on {len(on)} devices</span>'
        elif on:
            count += f' <span class="rem-count">on {_esc(on[0])}</span>'
        rows.append(
            f'<li class="rem-item"><span class="rem-rank">{i}</span>'
            f'<span class="chip" style="--c:{color}">{_esc(r["severity"])}</span>'
            f'<span class="rem-body"><span class="rem-title">{_esc(r["title"])}{count}</span>'
            f'<span class="rem-rec">{_esc(r["recommendation"])}</span></span></li>')
    if not rows:
        return '<p class="empty">Nothing to fix.</p>'
    return f'<ol class="rem-list">{"".join(rows)}</ol>'


def _devices_panel(ctx: ReportContext) -> str:
    devices = ctx.meta.get("devices")
    if not devices:
        return ""
    rows = []
    for d in devices:
        ds = ctx.summary.by_device.get(d["device"], {})
        sev = ds.get("by_severity", {})
        score = ds.get("overall_score", 100)
        grade, _ = score_band(score)
        color = _GRADE_COLOR[grade]
        crit, high = sev.get("Critical", 0), sev.get("High", 0)
        rows.append(
            f'<tr class="dev-row" data-device="{_esc(d["device"])}">'
            f'<td class="dev-name">{_esc(d["device"])}</td>'
            f'<td>{_esc(d.get("hostname") or "")}</td>'
            f'<td>{_esc(d.get("platform") or "unknown")}</td>'
            f'<td>{_esc(d.get("fortios_version") or "unknown")}</td>'
            f'<td>{_esc(", ".join(d.get("vdoms") or ["root"]))}</td>'
            f'<td class="num">{d.get("policy_count", 0)}</td>'
            f'<td class="num">{ds.get("total_findings", 0)}</td>'
            f'<td class="num{" crit" if crit else ""}">{crit}</td>'
            f'<td class="num{" high" if high else ""}">{high}</td>'
            f'<td class="num"><span class="dev-score" style="--c:{color}">{score} {grade}</span></td>'
            f'</tr>')
    skipped = ctx.meta.get("skipped_files") or []
    skip_note = _warn_box([f'<li><span class="dev-name">{_esc(sk["file"])}</span> was skipped: '
                           f'{_esc(sk["reason"])}</li>' for sk in skipped])
    return f"""
  <section class="panel" id="devices-section">
    <p class="sec-title">Devices (click one to list only its findings)</p>
    <div class="scroll"><table class="dev-table">
      <thead><tr><th>File</th><th>Hostname</th><th>Model</th><th>FortiOS</th><th>VDOMs</th>
        <th class="num">Rules</th><th class="num">Findings</th><th class="num">Critical</th>
        <th class="num">High</th><th class="num">Score</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table></div>
    {skip_note}
  </section>"""


_CSS = """
:root{
  --bg:#0c0e14; --panel:#141823; --panel-2:#1b2030; --border:#262c3d;
  --text:#e6e9f0; --muted:#8b93a8; --accent:#6ad7c7; --accent-dim:#3a7d74;
  --crit:#ff5c6c; --high:#ff9f43; --med:#ffd24c; --low:#4cc9f0; --info:#8b93a8;
  --mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 80px}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
.scroll{overflow-x:auto}
.lead{font-size:13px;color:var(--muted);margin:0 0 12px}
.lead b{color:var(--text)}
header.top{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;
  gap:20px;padding-bottom:16px;border-bottom:1px solid var(--border);margin-bottom:26px}
.brand h1{font-size:20px;margin:0;letter-spacing:.2px;font-weight:650}
.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}
.meta{font-family:var(--mono);font-size:12px;color:var(--muted);text-align:right;line-height:1.7}
.meta b{color:var(--text);font-weight:500}
section{margin:26px 0}
.sec-title{font-size:12px;text-transform:uppercase;letter-spacing:1.2px;
  color:var(--muted);margin:0 0 12px;font-weight:600}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px}
.grid{display:grid;gap:16px}
.cols-2{grid-template-columns:1fr 1fr}
@media(max-width:860px){.cols-2{grid-template-columns:1fr}}
.hero{display:grid;grid-template-columns:300px 1fr;gap:18px}
@media(max-width:860px){.hero{grid-template-columns:1fr}}
.gauge{width:100%;max-width:300px;display:block;margin:0 auto}
.gauge-score{font:700 46px var(--sans)}
.gauge-sub{fill:var(--muted);font:500 13px var(--mono)}
.gauge-word{font:700 13px var(--sans);letter-spacing:2px}
.hero-right{display:flex;flex-direction:column;justify-content:center;gap:14px}
.summary-text{color:var(--muted);font-size:14px;margin:0}
.summary-text b{color:var(--text)}
.stat-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px}
@media(max-width:860px){.stat-grid{grid-template-columns:repeat(3,1fr)}}
.stat{background:var(--panel-2);border:1px solid var(--border);border-radius:9px;
  padding:12px 10px;text-align:center}
.stat-val{font:700 24px var(--sans)}
.stat-label{font-size:11px;color:var(--muted);letter-spacing:.3px;margin-top:3px}
.stat.crit .stat-val{color:var(--crit)}
.stat.high .stat-val{color:var(--high)}
.donut{width:140px;height:140px;flex:none}
.donut-total{font:700 26px var(--sans);fill:var(--text)}
.donut-label{font:500 11px var(--mono);fill:var(--muted)}
.donut-wrap{display:flex;align-items:center;gap:18px}
.legend{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px;flex:1}
.legend li{display:flex;align-items:center;gap:9px;font-size:13px}
.legend .dot{width:11px;height:11px;border-radius:3px;flex:none}
.legend .lg-label{flex:1;color:var(--muted)}
.legend .lg-count{font-family:var(--mono);font-weight:600}
.bars{display:flex;flex-direction:column;gap:9px}
.bar-row{display:grid;grid-template-columns:170px 1fr 34px;align-items:center;gap:10px;font-size:12.5px}
.bar-label{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{height:9px;background:var(--panel-2);border-radius:6px;overflow:hidden}
.bar-fill{display:block;height:100%;background:var(--accent);border-radius:6px}
.bar-fill.soft{background:linear-gradient(90deg,var(--accent-dim),var(--accent))}
.bar-num{font-family:var(--mono);text-align:right;font-weight:600}
.heatmap{border-collapse:separate;border-spacing:3px;width:100%}
.heatmap th{font-weight:600;font-size:11px;color:var(--muted)}
.heatmap .hm-sev{text-align:center}
.heatmap .hm-cat{text-align:left;color:var(--text);font-weight:500;font-size:12px;padding-right:8px;white-space:nowrap}
.heatmap .hm-cell{min-width:64px;height:34px;text-align:center;border-radius:6px;
  font-family:var(--mono);font-weight:700;color:#0c0e14;cursor:pointer;transition:transform .08s}
.heatmap .hm-cell:hover{transform:scale(1.06)}
.heatmap .hm-empty{background:var(--panel-2)!important;color:#3a4257;cursor:default;opacity:1!important}
.risk-list,.rem-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
.risk-item{display:flex;align-items:center;gap:12px;background:var(--panel-2);
  border:1px solid var(--border);border-radius:9px;padding:9px 12px}
.risk-score{font-family:var(--mono);font-weight:700;font-size:15px;color:var(--c);min-width:34px;text-align:center}
.risk-body{flex:1;display:flex;flex-direction:column;min-width:0}
.risk-title{font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.risk-meta{font-size:11.5px;color:var(--muted);font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip{font-size:11px;font-weight:600;color:var(--c);border:1px solid var(--c);
  border-radius:20px;padding:2px 10px;white-space:nowrap;background:color-mix(in srgb,var(--c) 12%,transparent)}
.rem-item{display:flex;align-items:flex-start;gap:11px;background:var(--panel-2);
  border:1px solid var(--border);border-radius:9px;padding:10px 12px}
.rem-rank{font-family:var(--mono);color:var(--muted);font-weight:700;min-width:20px}
.rem-body{flex:1;min-width:0}
.rem-title{font-weight:550}
.rem-count{font-family:var(--mono);color:var(--muted);font-size:12px;font-weight:600}
.rem-rec{display:block;color:var(--muted);font-size:12.5px;margin-top:3px}
.exp-table,.cov-table{width:100%;border-collapse:collapse;font-size:12.5px}
.exp-table th,.cov-table th{text-align:left;color:var(--accent);font-size:11px;text-transform:uppercase;
  letter-spacing:.6px;padding:6px 9px;border-bottom:1px solid var(--border);white-space:nowrap}
.exp-table td,.cov-table td{padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:top}
.exp-table td{font-family:var(--mono);font-size:11.5px}
.exp-table td.exp-prof{font-family:var(--sans);font-size:12px;color:var(--muted)}
.exp-none{color:var(--crit);font-weight:700}
.exp-vdom{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin:14px 0 6px;font-weight:600}
.natmode{font-size:12.5px;color:var(--muted);margin:0 0 4px}
.natmode b{color:var(--accent);font-weight:600}
.cov-dom{font-weight:600;white-space:nowrap}
.cov-count{display:inline-block;margin-left:8px;font-weight:500;color:var(--muted);font-family:var(--mono);font-size:11px}
.cov-note{color:var(--muted);font-size:12px}
.cov-badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:10.5px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.cov-ok{background:rgba(106,215,199,.13);color:var(--accent);border-color:rgba(106,215,199,.32)}
.cov-ref{background:rgba(76,201,240,.12);color:var(--low);border-color:rgba(76,201,240,.3)}
.cov-bad{background:rgba(255,92,108,.13);color:var(--crit);border-color:rgba(255,92,108,.34)}
.cov-absent{background:var(--panel-2);color:#5a627a;border-color:var(--border)}
.cov-warn{margin-top:14px;background:var(--panel-2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:11px 14px}
.cov-warn b{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--accent)}
.cov-warn ul{margin:7px 0 0;padding-left:18px}
.cov-warn li{font-size:12.5px;color:var(--muted);margin:4px 0;line-height:1.5}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}
.controls input[type=search],.controls select{background:var(--panel-2);
  border:1px solid var(--border);color:var(--text);border-radius:8px;
  padding:8px 11px;font-size:13px;font-family:var(--sans)}
.controls input[type=search]{min-width:230px;flex:1}
.sevfilters{display:flex;gap:6px;flex-wrap:wrap}
.sevbtn{cursor:pointer;font-size:11.5px;font-weight:600;border-radius:20px;
  padding:5px 11px;border:1px solid var(--c);color:var(--c);background:transparent;user-select:none}
.sevbtn.off{opacity:.32;filter:grayscale(.5)}
.count-note{color:var(--muted);font-size:12px;font-family:var(--mono);margin-left:auto}
table.findings{width:100%;border-collapse:collapse}
table.findings thead th{position:sticky;top:0;background:var(--panel);
  text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.7px;
  color:var(--muted);padding:9px 10px;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap}
table.findings thead th .arrow{opacity:.5;font-size:9px}
table.findings tbody tr.row{border-bottom:1px solid var(--border);cursor:pointer}
table.findings tbody tr.row:hover{background:var(--panel-2)}
table.findings td{padding:9px 10px;vertical-align:top;font-size:13px}
.sev-pill{display:inline-block;font-weight:600;font-size:11.5px;color:var(--c);border-left:3px solid var(--c);padding-left:8px}
.risk-cell{font-family:var(--mono);font-weight:600}
.obj-cell{font-family:var(--mono);font-size:12px;color:var(--muted);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vd-cell{font-family:var(--mono);font-size:12px}
.dev-cell{white-space:nowrap}
tr.detail td{background:var(--panel-2);padding:0}
.detail-inner{padding:16px 18px;display:grid;grid-template-columns:1fr 320px;gap:20px}
@media(max-width:860px){.detail-inner{grid-template-columns:1fr}}
.detail h4{margin:0 0 5px;font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--accent)}
.detail p{margin:0 0 12px;font-size:13px}
.evidence{font-family:var(--mono);font-size:12px;background:#0a0c12;border:1px solid var(--border);
  border-radius:8px;padding:10px 12px;white-space:pre-wrap;word-break:break-word;color:#c9d3e6;margin-bottom:12px}
.kv{font-size:12px;color:var(--muted);margin-bottom:7px}
.kv b{color:var(--text);font-weight:550}
.cmp{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 12px}
.cmp .tag2{font-family:var(--mono);font-size:11px;background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:3px 8px;color:var(--muted)}
.refs{list-style:none;padding:0;margin:0;font-size:12px}
.refs li{margin-bottom:4px;word-break:break-all}
.gauge-cap{margin:2px 0 0;text-align:center;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.dev-table{width:100%;border-collapse:collapse;font-size:12.5px}
.dev-table th{text-align:left;color:var(--accent);font-size:11px;text-transform:uppercase;
  letter-spacing:.6px;padding:6px 9px;border-bottom:1px solid var(--border);white-space:nowrap}
.dev-table td{padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:top}
.dev-table .num{text-align:right;font-family:var(--mono)}
.dev-table td.crit{color:var(--crit);font-weight:700}
.dev-table td.high{color:var(--high);font-weight:700}
.dev-row{cursor:pointer}
.dev-row:hover{background:var(--panel-2)}
.dev-name{font-family:var(--mono);font-weight:600;white-space:nowrap;color:var(--text)}
.dev-score{font-weight:700;color:var(--c)}
.exp-dev{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text);margin:20px 0 6px;
  padding-top:12px;border-top:1px solid var(--border)}
.lead + .exp-box .exp-dev{margin-top:0;padding-top:0;border-top:0}
.cov-who{font-family:var(--mono);font-size:11px;color:var(--accent)}
.pager{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:flex-end;margin-top:14px}
.pager .sevbtn.off{pointer-events:none}
.pg-info{color:var(--muted);font-size:12px;font-family:var(--mono)}
.pager select{background:var(--panel-2);border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:6px 9px;font-size:12px;font-family:var(--sans)}
.ip-cell{font-family:var(--mono);font-size:11.5px;white-space:nowrap}
.muted{color:var(--muted)}
.detail-wide{grid-column:1/-1}
.ip-table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:4px}
.ip-table th{text-align:left;color:var(--accent);font-size:10.5px;text-transform:uppercase;
  letter-spacing:.6px;padding:5px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
.ip-table td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
.ip-table .ip-val{font-family:var(--mono);font-weight:600;white-space:nowrap}
.ip-table .ip-line{font-family:var(--mono);color:var(--muted);padding-right:14px}
.ip-table .ip-set{font-family:var(--mono);color:#c9d3e6;word-break:break-word}
.ip-table .ip-set .muted{font-family:var(--sans);margin-top:2px}
details.exp-box > summary{cursor:pointer;list-style:none}
details.exp-box > summary::-webkit-details-marker{display:none}
details.exp-box > summary .exp-dev::before{content:"▸  ";color:var(--muted)}
details.exp-box[open] > summary .exp-dev::before{content:"▾  "}
.hidden{display:none!important}
footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--border);color:var(--muted);font-size:12px;line-height:1.7}
@media print{body{background:#fff;color:#000}.panel{border-color:#ccc}.controls{display:none}}
"""

_JS = r"""
(function(){
  var DATA = JSON.parse(document.getElementById("__FGAUDIT__").textContent);
  var F = DATA.findings, T = DATA.texts, IPS = DATA.ips, V = DATA.vdoms, D = DATA.devices;
  var X = DATA.exposures, C = DATA.confidences, SEV = DATA.sev, SEV_COLOR = DATA.sevColor;
  var fleet = D.length > 0;
  var cols = fleet ? 8 : 7;
  var state = {q:"", sevs:new Set(SEV.map(function(_, i){ return i; })), device:-1, vdom:-1,
               cat:"*", sort:"risk_score", dir:-1, page:0, size:100};
  var order = null, view = [], hay = null, opened = {}, timer = null;
  var tbody = document.getElementById("fbody");
  var note = document.getElementById("count-note");
  var info = document.getElementById("pg-info");
  var prev = document.getElementById("pg-prev");
  var next = document.getElementById("pg-next");
  var search = document.getElementById("search");
  var vsel = document.getElementById("vdom-select");
  var csel = document.getElementById("cat-select");
  var dsel = document.getElementById("device-select");
  var zsel = document.getElementById("pg-size");
  var section = document.getElementById("findings-section");
  var ESC = {"&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"};

  function esc(s){ return s == null ? "" : String(s).replace(/[&<>"']/g, function(c){ return ESC[c]; }); }
  function fmt(n){ return n.toLocaleString(); }

  function sortValue(f){
    switch(state.sort){
      case "severity": return f.s;
      case "device": return fleet ? (D[f.n] || "") : "";
      case "vdom": return V[f.v];
      case "category": return T[f.t][2];
      case "title": return T[f.t][1].toLowerCase();
      default: return f.k;
    }
  }

  function resort(){
    var keys = F.map(sortValue), dir = state.dir;
    order = F.map(function(_, i){ return i; });
    order.sort(function(a, b){
      var ka = keys[a], kb = keys[b];
      if(ka < kb) return -dir;
      if(ka > kb) return dir;
      return F[b].k - F[a].k;
    });
  }

  function haystack(i){
    if(!hay) hay = new Array(F.length);
    var h = hay[i];
    if(h === undefined){
      var f = F[i], t = T[f.t];
      var parts = [t[0], t[1], f.o, f.d, V[f.v], fleet ? D[f.n] : ""];
      (f.i || []).forEach(function(r){
        var ref = IPS[r];
        parts.push(ref[4].join(" "), ref[3], ref[0]);
      });
      h = hay[i] = parts.join(" ").toLowerCase();
    }
    return h;
  }

  function passes(i){
    var f = F[i];
    if(!state.sevs.has(f.s)) return false;
    if(state.device !== -1 && f.n !== state.device) return false;
    if(state.vdom !== -1 && f.v !== state.vdom) return false;
    if(state.cat !== "*" && T[f.t][2] !== state.cat) return false;
    if(state.q && haystack(i).indexOf(state.q) < 0) return false;
    return true;
  }

  function refilter(){
    if(!order) resort();
    view = order.filter(passes);
    state.page = 0;
    render();
  }

  function ipSummary(f){
    var seen = [];
    (f.i || []).forEach(function(r){
      IPS[r][4].forEach(function(v){ if(seen.indexOf(v) < 0) seen.push(v); });
    });
    if(!seen.length) return '<span class="muted">&ndash;</span>';
    var shown = seen.slice(0, 2).map(esc).join(", ");
    return seen.length > 2 ? shown + ' <span class="muted">+' + (seen.length - 2) + '</span>' : shown;
  }

  function ipTable(f){
    var refs = f.i || [];
    if(!refs.length) return '<p class="kv">Nothing in the config for this finding carries an IP address.</p>';
    var rows = refs.map(function(r){
      var ref = IPS[r];
      var ips = ref[4].length ? ref[4].map(esc).join("<br>") : '<span class="muted">no IP address</span>';
      if(ref[5]) ips += '<br><span class="muted">and ' + ref[5] + ' more</span>';
      return '<tr><td class="ip-val">' + ips + '</td><td>' + esc(ref[0]) + '</td>'
        + '<td class="ip-line">' + (ref[1] || "") + '</td>'
        + '<td class="ip-set">set ' + esc(ref[2]) + ' ' + esc(ref[3])
        + (ref[6] ? '<div class="muted">' + esc(ref[6]) + '</div>' : '') + '</td></tr>';
    }).join("");
    return '<div class="scroll"><table class="ip-table"><thead><tr><th>IP addresses</th>'
      + '<th>Where in the config</th><th>Line</th><th>As written</th></tr></thead><tbody>'
      + rows + '</tbody></table></div>';
  }

  function detailHtml(i){
    var f = F[i], t = T[f.t];
    var cmp = Object.keys(t[6] || {}).map(function(k){
      return '<span class="tag2">' + esc(k) + ' ' + esc((t[6][k] || []).join(", ")) + '</span>';
    }).join("");
    var refs = (t[5] || []).map(function(u){
      return u.indexOf("http") === 0
        ? '<li><a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(u) + '</a></li>'
        : '<li>' + esc(u) + '</li>';
    }).join("");
    var ev = (f.e || []).map(esc).join("\n");
    return '<div class="detail-inner detail"><div>'
      + '<h4>What we found</h4><p>' + esc(f.d) + '</p>'
      + '<h4>Why it matters</h4><p>' + esc(t[3]) + '</p>'
      + '<h4>How to fix</h4><p>' + esc(t[4]) + '</p>'
      + (ev ? ('<h4>Evidence from the config</h4><div class="evidence">' + ev + '</div>') : '')
      + '</div><div>'
      + (fleet ? '<div class="kv"><b>Device</b> ' + esc(D[f.n]) + '</div>' : '')
      + '<div class="kv"><b>Rule</b> ' + esc(t[0]) + '</div>'
      + '<div class="kv"><b>ID</b> ' + esc(f.u) + '</div>'
      + '<div class="kv"><b>Confidence</b> ' + esc(C[f.c]) + '</div>'
      + '<div class="kv"><b>Exposure</b> ' + esc(X[f.x]) + '</div>'
      + '<div class="kv"><b>Risk score</b> ' + f.k + ' of 100</div>'
      + '<h4>Related controls</h4>' + (cmp ? ('<div class="cmp">' + cmp + '</div>') : '<p class="kv">None mapped.</p>')
      + (refs ? ('<h4>References</h4><ul class="refs">' + refs + '</ul>') : '')
      + '</div><div class="detail-wide"><h4>IP addresses from the config</h4>' + ipTable(f)
      + '</div></div>';
  }

  function detailRow(i){
    return '<tr class="detail" data-detail="' + i + '"><td colspan="' + cols + '">' + detailHtml(i) + '</td></tr>';
  }

  function render(){
    var total = view.length, size = state.size;
    var pages = Math.max(1, Math.ceil(total / size));
    if(state.page >= pages) state.page = pages - 1;
    var start = state.page * size, end = Math.min(total, start + size);
    var out = [];
    for(var p = start; p < end; p++){
      var i = view[p], f = F[i], t = T[f.t], c = SEV_COLOR[SEV[f.s]] || "#888";
      out.push('<tr class="row" data-i="' + i + '">'
        + '<td><span class="sev-pill" style="--c:' + c + '">' + SEV[f.s] + '</span></td>'
        + '<td class="risk-cell" style="color:' + c + '">' + f.k + '</td>'
        + (fleet ? '<td class="vd-cell dev-cell">' + esc(D[f.n]) + '</td>' : '')
        + '<td class="vd-cell">' + esc(V[f.v]) + '</td>'
        + '<td>' + esc(t[2]) + '</td>'
        + '<td>' + esc(t[1]) + '</td>'
        + '<td class="obj-cell" title="' + esc(f.o) + '">' + esc(f.o) + '</td>'
        + '<td class="ip-cell">' + ipSummary(f) + '</td></tr>');
      if(opened[i]) out.push(detailRow(i));
    }
    tbody.innerHTML = out.join("") || '<tr><td colspan="' + cols + '" class="empty">No findings match these filters.</td></tr>';
    note.textContent = total === F.length ? fmt(total) + " findings"
      : fmt(total) + " of " + fmt(F.length) + " findings match";
    info.textContent = total ? fmt(start + 1) + "–" + fmt(end) + " of " + fmt(total)
      + " · page " + fmt(state.page + 1) + " of " + fmt(pages) : "";
    prev.classList.toggle("off", state.page === 0);
    next.classList.toggle("off", state.page >= pages - 1);
  }

  function goTo(page){
    var pages = Math.max(1, Math.ceil(view.length / state.size));
    if(page < 0 || page >= pages || page === state.page) return;
    state.page = page;
    render();
    if(section.getBoundingClientRect().top < 0) section.scrollIntoView();
  }

  function updateArrows(){
    Array.prototype.forEach.call(document.querySelectorAll("th[data-sort] .arrow"), function(a){ a.textContent = ""; });
    var th = document.querySelector('th[data-sort="' + state.sort + '"] .arrow');
    if(th) th.textContent = state.dir < 0 ? " ▼" : " ▲";
  }

  function showOnly(sev){
    state.sevs = new Set([SEV.indexOf(sev)]);
    Array.prototype.forEach.call(document.querySelectorAll(".sevbtn[data-sev]"), function(b){
      b.classList.toggle("off", b.getAttribute("data-sev") !== sev);
    });
  }

  tbody.addEventListener("click", function(e){
    var tr = e.target.closest ? e.target.closest("tr.row") : null;
    if(!tr) return;
    var i = +tr.getAttribute("data-i");
    var sib = tr.nextElementSibling;
    if(opened[i]){
      delete opened[i];
      if(sib && sib.classList.contains("detail")) sib.parentNode.removeChild(sib);
    } else {
      opened[i] = true;
      tr.insertAdjacentHTML("afterend", detailRow(i));
    }
  });

  Array.prototype.forEach.call(document.querySelectorAll("th[data-sort]"), function(th){
    th.addEventListener("click", function(){
      var key = th.getAttribute("data-sort");
      if(state.sort === key){ state.dir *= -1; }
      else { state.sort = key; state.dir = (key === "title" || key === "vdom" || key === "category" || key === "device") ? 1 : -1; }
      updateArrows(); resort(); refilter();
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll(".sevbtn[data-sev]"), function(btn){
    btn.addEventListener("click", function(){
      var s = SEV.indexOf(btn.getAttribute("data-sev"));
      if(state.sevs.has(s)){ state.sevs.delete(s); btn.classList.add("off"); }
      else { state.sevs.add(s); btn.classList.remove("off"); }
      refilter();
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll(".hm-cell[data-cat]"), function(cell){
    cell.addEventListener("click", function(){
      state.cat = cell.getAttribute("data-cat"); csel.value = state.cat;
      showOnly(cell.getAttribute("data-sev"));
      section.scrollIntoView({behavior:"smooth"});
      refilter();
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll("tr.dev-row[data-device]"), function(tr){
    tr.addEventListener("click", function(){
      var name = tr.getAttribute("data-device");
      state.device = D.indexOf(name); if(dsel) dsel.value = name;
      section.scrollIntoView({behavior:"smooth"});
      refilter();
    });
  });

  search.addEventListener("input", function(){
    clearTimeout(timer);
    timer = setTimeout(function(){ state.q = search.value.toLowerCase().trim(); refilter(); }, 180);
  });
  vsel.addEventListener("change", function(){
    state.vdom = vsel.value === "*" ? -1 : V.indexOf(vsel.value);
    if(state.vdom === -1 && vsel.value !== "*") state.vdom = -2;
    refilter();
  });
  csel.addEventListener("change", function(){ state.cat = csel.value; refilter(); });
  if(dsel) dsel.addEventListener("change", function(){
    state.device = dsel.value === "*" ? -1 : D.indexOf(dsel.value);
    refilter();
  });
  zsel.addEventListener("change", function(){ state.size = +zsel.value; state.page = 0; render(); });
  prev.addEventListener("click", function(){ goTo(state.page - 1); });
  next.addEventListener("click", function(){ goTo(state.page + 1); });

  document.getElementById("expand-all").addEventListener("click", function(){
    var start = state.page * state.size, ids = view.slice(start, start + state.size);
    var anyClosed = ids.some(function(i){ return !opened[i]; });
    ids.forEach(function(i){ if(anyClosed) opened[i] = true; else delete opened[i]; });
    render();
  });

  updateArrows();
  refilter();
})();
"""


_EXPOSURES = [e.value for e in Exposure]
_CONFIDENCES = [c.value for c in Confidence]


def _payload(ctx: ReportContext, devices: list[dict]) -> dict:
    sev_index = {sev: i for i, sev in enumerate(Severity)}
    exp_index = {e: i for i, e in enumerate(Exposure)}
    conf_index = {c: i for i, c in enumerate(Confidence)}
    device_index = {d["device"]: i for i, d in enumerate(devices)}
    texts: dict[tuple, int] = {}
    text_rows: list[list] = []
    ip_index: dict[IpRef, int] = {}
    ip_rows: list[list] = []
    vdoms: dict[str, int] = {}
    rows: list[dict] = []
    for f in ctx.findings:
        compliance = {k: list(v) for k, v in f.compliance.items()}
        key = (f.rule_id, f.title, str(f.category), f.impact, f.recommendation,
               tuple(f.references), tuple((k, tuple(v)) for k, v in compliance.items()))
        t = texts.get(key)
        if t is None:
            t = texts[key] = len(text_rows)
            text_rows.append([f.rule_id, f.title, str(f.category), f.impact, f.recommendation,
                              list(f.references), compliance])
        row = {"t": t, "s": sev_index[f.severity], "k": f.risk_score,
               "v": vdoms.setdefault(f.vdom, len(vdoms)), "x": exp_index[f.exposure],
               "c": conf_index[f.confidence], "o": f.affected_object, "d": f.description,
               "e": f.evidence, "u": f.unique_id}
        if devices:
            row["n"] = device_index.get(f.device, -1)
        if f.ips:
            refs = []
            for ref in f.ips:
                idx = ip_index.get(ref)
                if idx is None:
                    idx = ip_index[ref] = len(ip_rows)
                    ip_rows.append([ref.source, ref.line, ref.setting, ref.written,
                                    list(ref.ips), ref.more, ref.note])
                refs.append(idx)
            row["i"] = refs
        rows.append(row)
    return {"findings": rows, "texts": text_rows, "ips": ip_rows, "vdoms": list(vdoms),
            "devices": [d["device"] for d in devices], "sev": SEV_ORDER, "sevColor": SEV_COLOR,
            "exposures": _EXPOSURES, "confidences": _CONFIDENCES}


def _summary_sentence(ctx: ReportContext) -> str:
    s = ctx.summary
    grade, word = score_band(s.overall_score)
    crit = s.by_severity.get("Critical", 0)
    high = s.by_severity.get("High", 0)
    internet = s.by_exposure.get("internet-facing", 0)
    if s.total_findings == 0:
        if ctx.meta.get("devices"):
            return (f"The review found nothing to report on any of the "
                    f"<b>{len(ctx.meta['devices'])}</b> devices.")
        return "The review found nothing to report."
    serious = []
    if crit:
        serious.append(f"<b>{crit}</b> critical")
    if high:
        serious.append(f"<b>{high}</b> high")
    serious_text = (" Of these, " + " and ".join(serious) + " need attention first."
                    if serious else " None of them are critical or high.")
    internet_text = (f" <b>{internet}</b> involve traffic from the internet." if internet else "")
    devices = ctx.meta.get("devices")
    if devices:
        weakest = min(s.by_device, key=lambda d: s.by_device[d]["overall_score"])
        return (f"The review found <b>{s.total_findings}</b> issues in "
                f"<b>{len(s.by_category)}</b> areas across <b>{len(devices)}</b> devices."
                f"{serious_text}{internet_text} The weakest device, <b>{_esc(weakest)}</b>, "
                f"scores <b>{s.overall_score}</b> out of 100, grade <b>{grade}</b> ({word}).")
    return (f"The review found <b>{s.total_findings}</b> issues in "
            f"<b>{len(s.by_category)}</b> areas.{serious_text}{internet_text} Overall the "
            f"configuration scores <b>{s.overall_score}</b> out of 100, grade <b>{grade}</b> "
            f"({word}).")


class HtmlReporter(Reporter):
    extension = "html"

    def render(self, ctx: ReportContext) -> str:
        s = ctx.summary
        meta = ctx.meta
        devices = meta.get("devices") or []
        vdoms = meta.get("vdoms") or []
        vdom_opts = "".join(f'<option value="{_esc(v)}">{_esc(v)}</option>'
                            for v in sorted(set(vdoms)))
        device_select = ""
        device_head = ""
        if devices:
            device_opts = "".join(f'<option value="{_esc(d["device"])}">{_esc(d["device"])}</option>'
                                  for d in devices)
            device_select = (f'<select id="device-select"><option value="*">All devices</option>'
                             f'{device_opts}</select>')
            device_head = '<th data-sort="device">Device<span class="arrow"></span></th>'
        cat_opts = "".join(f'<option value="{_esc(c)}">{_esc(c)}</option>'
                           for c in CAT_ORDER if c in s.by_category)
        sev_buttons = "".join(
            f'<span class="sevbtn" data-sev="{_esc(sev)}" style="--c:{SEV_COLOR[sev]}">{_esc(sev)}</span>'
            for sev in SEV_ORDER)
        data_json = json.dumps(_payload(ctx, devices), ensure_ascii=False,
                               separators=(",", ":")).replace("<", "\\u003c")

        if devices:
            meta_block = (
                f'<div><b>Folder</b> {_esc(meta.get("source_file", "n/a"))}</div>'
                f'<div><b>Devices</b> {len(devices)} &middot; <b>VDOMs</b> {len(vdoms) or 1}</div>'
                f'<div><b>Rules</b> {meta.get("policy_count", "n/a")}</div>'
                f'<div><b>Reviewed</b> {_esc(meta.get("generated_at", ""))}</div>')
            tagline = f"An offline security review of {len(devices)} FortiGate backup files."
            gauge_cap = '<p class="gauge-cap">Lowest device score</p>'
        else:
            device = (f'{_esc(meta.get("platform") or "unknown model")}, FortiOS '
                      f'{_esc(meta.get("fortios_version", "unknown"))}')
            meta_block = (
                f'<div><b>File</b> {_esc(meta.get("source_file", "n/a"))}</div>'
                f'<div><b>Device</b> {device}</div>'
                f'<div><b>VDOMs</b> {len(vdoms) or 1} &middot; <b>Rules</b> '
                f'{meta.get("policy_count", "n/a")}</div>'
                f'<div><b>Reviewed</b> {_esc(meta.get("generated_at", ""))}</div>')
            tagline = "An offline security review of a FortiGate backup file."
            gauge_cap = ""
        by_category = [(c, s.by_category.get(c, 0)) for c in CAT_ORDER]

        body = f"""<div class="wrap">
  <header class="top">
    <div class="brand">
      <h1>FortiGate configuration review</h1>
      <p>{tagline}</p>
    </div>
    <div class="meta">{meta_block}</div>
  </header>

  <section>
    <div class="panel hero">
      <div>{_gauge_svg(s.overall_score)}{gauge_cap}</div>
      <div class="hero-right">
        <p class="summary-text">{_summary_sentence(ctx)}</p>
        {_stat_cards(ctx)}
      </div>
    </div>
  </section>
{_devices_panel(ctx)}

  <section class="grid cols-2">
    <div class="panel">
      <p class="sec-title">Findings by severity</p>
      <div class="donut-wrap">{_donut_svg(s.by_severity)}{_legend(s.by_severity)}</div>
    </div>
    <div class="panel">
      <p class="sec-title">Findings by area</p>
      {_bars(by_category)}
    </div>
  </section>

  <section class="panel">
    <p class="sec-title">Where the problems are (click a cell to filter the list below)</p>
    {_heatmap(s.heatmap)}
  </section>

  <section class="grid cols-2">
    <div class="panel">
      <p class="sec-title">Fix these first</p>
      {_top_risks(ctx)}
    </div>
    <div class="panel">
      <p class="sec-title">Compliance frameworks touched</p>
      {_bars(list(s.compliance_hits.items()), "soft")}
    </div>
  </section>
{_exposure_panel(meta)}
  <section class="panel">
    <p class="sec-title">What to fix, in order</p>
    {_remediation(ctx)}
  </section>
{_coverage_panel(meta)}
  <section class="panel" id="findings-section">
    <p class="sec-title">All findings (click a row for details)</p>
    <div class="controls">
      <input type="search" id="search" placeholder="Search findings, objects, rule IDs, IPs">
      <div class="sevfilters">{sev_buttons}</div>
      {device_select}
      <select id="vdom-select"><option value="*">All VDOMs</option>{vdom_opts}</select>
      <select id="cat-select"><option value="*">All areas</option>{cat_opts}</select>
      <span class="sevbtn" id="expand-all" style="--c:var(--accent)">Open or close all</span>
      <span class="count-note" id="count-note"></span>
    </div>
    <div class="scroll"><table class="findings">
      <thead><tr>
        <th data-sort="severity">Severity<span class="arrow"></span></th>
        <th data-sort="risk_score">Risk<span class="arrow"></span></th>
        {device_head}
        <th data-sort="vdom">VDOM<span class="arrow"></span></th>
        <th data-sort="category">Area<span class="arrow"></span></th>
        <th data-sort="title">Finding<span class="arrow"></span></th>
        <th>Affects</th>
        <th>IPs</th>
      </tr></thead>
      <tbody id="fbody"></tbody>
    </table></div>
    <div class="pager">
      <span class="sevbtn" id="pg-prev" style="--c:var(--accent)">&lsaquo; Previous</span>
      <span class="pg-info" id="pg-info"></span>
      <span class="sevbtn" id="pg-next" style="--c:var(--accent)">Next &rsaquo;</span>
      <select id="pg-size"><option value="50">50 per page</option>
        <option value="100" selected>100 per page</option><option value="250">250 per page</option>
        <option value="500">500 per page</option></select>
    </div>
  </section>

  <footer>
    <div>Made by fgaudit {_esc(meta.get("tool_version", ""))}. The risk score of each finding
      combines its severity, how sure the check is and whether the problem can be reached from
      the internet. The overall score starts at 100 and drops a little for every finding, more
      for serious ones.</div>
    <div>This is an offline review of a configuration file. Nothing was scanned or tested on
      the device. Check each finding against how the network is really used before you change
      anything.</div>
  </footer>
</div>
<script type="application/json" id="__FGAUDIT__">{data_json}</script>
<script>{_JS}</script>"""

        return (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>FortiGate review: {_esc(meta.get('source_file', ''))}</title>\n"
            f"<style>{_CSS}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n"
        )
