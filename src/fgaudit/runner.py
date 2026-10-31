from __future__ import annotations

import datetime as _dt
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .analyzers import AnalyzerConfig, AnalyzerContext, get_analyzers
from .coverage import CoverageReport, build_coverage
from .findings import Finding
from .ip_evidence import attach_ips
from .models import ConfigModel
from .object_resolver import ObjectResolver, SetResolver
from .parser import parse_config
from .scoring import Summary, build_summary

logger = logging.getLogger(__name__)

__version__ = "2.1.0"

_HEADER_RE = re.compile(r"#config-version=(?P<payload>\S+)")
_FULL_DUMP_GLOBAL_KEYS = 80


def _extract_meta(text: str, model: ConfigModel) -> dict:
    version = "unknown"
    platform = None
    build = None
    raw_header = None
    vdom_flag = False

    for line in text.lstrip("﻿").splitlines()[:10]:
        m = _HEADER_RE.search(line)
        if not m:
            continue
        raw_header = line.strip()
        payload = m.group("payload")
        parts = payload.split(":", 1)[0].split("-")
        if parts:
            platform = parts[0]
        if len(parts) > 1 and re.match(r"\d+\.\d+", parts[1]):
            version = parts[1]
        for p in parts:
            if p.startswith("build"):
                build = p[len("build"):]
        for kv in payload.split(":"):
            if kv.startswith("vdom="):
                vdom_flag = kv.split("=", 1)[1] not in ("0", "")
        break

    g = model.first("system global")
    return {
        "tool": "fgaudit",
        "tool_version": __version__,
        "fortios_version": version,
        "platform": platform,
        "build": build,
        "hostname": g.get("hostname") if g is not None else None,
        "raw_header": raw_header,
        "multi_vdom": model.multi_vdom or vdom_flag,
        "vdoms": list(model.vdoms),
        "policy_count": model.count("firewall policy") + model.count("firewall policy6"),
        "source_lines": model.source_lines,
        "section_count": len(model.sections_present()),
        "dump_style": _dump_style(model),
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _dump_style(model: ConfigModel) -> str:
    g = model.first("system global")
    if g is None:
        return "unknown"
    return "full" if len(g.settings) >= _FULL_DUMP_GLOBAL_KEYS else "standard"


@dataclass(slots=True)
class AuditResult:
    findings: list[Finding]
    summary: Summary
    meta: dict = field(default_factory=dict)
    coverage: Optional[CoverageReport] = None
    artifacts: dict = field(default_factory=dict)


def run_audit(
    text: str,
    *,
    wan_interfaces: Optional[Iterable[str]] = None,
    config: Optional[AnalyzerConfig] = None,
    source_file: str = "config",
    hit_counts: Optional[dict] = None,
    psirt_feed: Optional[dict] = None,
) -> AuditResult:
    started = time.perf_counter()
    model = parse_config(text)
    logger.info("Parsed %d lines into %d VDOM(s): %s",
                model.source_lines, len(model.vdoms), ", ".join(model.vdoms))

    sets = SetResolver(model)
    resolver = ObjectResolver(model, wan_interfaces=wan_interfaces, sets=sets)
    coverage = build_coverage(model, resolver.reference_index)
    meta = _extract_meta(text, model)
    meta["source_file"] = source_file

    if meta["dump_style"] == "standard":
        coverage.warnings.append(
            "This looks like a normal backup, which leaves out every setting that is at its "
            "factory default. The review reads a missing setting as the FortiOS default.")
    if hit_counts is None:
        coverage.warnings.append(
            "No hit counters were given (--hit-counts), so rules that are enabled but never "
            "used can't be found.")
    if resolver.wan_confidence_low():
        coverage.warnings.append(
            "No interface is clearly internet-facing (no wan role, default route, DHCP/PPPoE "
            "uplink or public address), so the review guessed from interface names. Use --wan "
            "to name the internet-facing interfaces.")

    ctx = AnalyzerContext(
        model, resolver, sets=sets, config=config, coverage=coverage,
        meta=meta, hit_counts=hit_counts, psirt_feed=psirt_feed,
    )

    findings: list[Finding] = []
    for analyzer in get_analyzers():
        try:
            produced = analyzer.analyze(ctx)
        except Exception:
            logger.exception("Analyzer %r failed; continuing without it", analyzer.name)
            coverage.warnings.append(
                f"The {analyzer.name} check crashed on this backup and was skipped. "
                f"Run with -vv to see why.")
            continue
        logger.info("Analyzer %-18s -> %d finding(s)", analyzer.name, len(produced))
        findings.extend(produced)

    try:
        attach_ips(findings, model, sets, resolver)
    except Exception:
        logger.exception("Working out the IP addresses behind the findings failed")
        coverage.warnings.append(
            "The IP addresses behind the findings couldn't be worked out for this backup, so "
            "findings are shown without them. Run with -vv to see why.")

    summary = build_summary(findings)
    meta["duration_seconds"] = round(time.perf_counter() - started, 3)
    meta["coverage"] = coverage.to_dict()
    meta["exposure_map"] = ctx.artifacts.get("exposure_map", {})
    meta["nat_mode"] = ctx.artifacts.get("nat_mode", {})
    meta["internet_facing_interfaces"] = sorted(resolver.internet_facing_interfaces)
    if sets.cycles:
        meta["object_cycles"] = sorted(set(sets.cycles))
    logger.info("Done: %d findings, score %d/100 in %.2fs",
                len(findings), summary.overall_score, meta["duration_seconds"])
    public_artifacts = {k: v for k, v in ctx.artifacts.items() if not k.startswith("_")}
    return AuditResult(findings=findings, summary=summary, meta=meta,
                       coverage=coverage, artifacts=public_artifacts)


CONFIG_SUFFIX = ".conf"
_FOLDER_ONLY_META = ("tool", "tool_version", "generated_at")


def find_configs(folder: Path) -> list[Path]:
    return sorted((p for p in folder.iterdir()
                   if p.is_file() and p.suffix.lower() == CONFIG_SUFFIX),
                  key=lambda p: p.name.lower())


def hit_counts_for(hit_counts: Optional[dict], path: Path) -> Optional[dict]:
    if not hit_counts:
        return None
    found = hit_counts.get(path.name, hit_counts.get(path.stem))
    return found if isinstance(found, dict) else None


def run_folder_audit(
    paths: Iterable[Path],
    *,
    wan_interfaces: Optional[Iterable[str]] = None,
    config: Optional[AnalyzerConfig] = None,
    source_dir: str = "configs",
    hit_counts: Optional[dict] = None,
    psirt_feed: Optional[dict] = None,
) -> AuditResult:
    started = time.perf_counter()
    wan = list(wan_interfaces) if wan_interfaces is not None else None
    findings: list[Finding] = []
    devices: list[dict] = []
    skipped: list[dict] = []

    for path in paths:
        name = path.name
        logger.info("Reviewing %s", path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            skipped.append({"file": name, "reason": f"couldn't be read: {exc}"})
            continue
        try:
            result = run_audit(text, wan_interfaces=wan, config=config, source_file=name,
                               hit_counts=hit_counts_for(hit_counts, path),
                               psirt_feed=psirt_feed)
        except Exception:
            logger.exception("Review of %s failed; continuing without it", path)
            skipped.append({"file": name,
                            "reason": "the review crashed on it; run with -vv to see why"})
            continue
        if not result.meta.get("section_count"):
            skipped.append({"file": name,
                            "reason": "doesn't look like a FortiGate configuration (no 'config' "
                                      "blocks found); it may be an encrypted backup"})
            continue
        for f in result.findings:
            f.assign_device(name)
        findings.extend(result.findings)
        device = {"device": name}
        device.update((k, v) for k, v in result.meta.items() if k not in _FOLDER_ONLY_META)
        devices.append(device)

    names = [d["device"] for d in devices]
    summary = build_summary(findings, devices=names)
    meta = {
        "tool": "fgaudit",
        "tool_version": __version__,
        "source_file": source_dir,
        "device_count": len(devices),
        "devices": devices,
        "skipped_files": skipped,
        "vdoms": sorted({v for d in devices for v in d.get("vdoms", [])}),
        "policy_count": sum(d.get("policy_count", 0) for d in devices),
        "source_lines": sum(d.get("source_lines", 0) for d in devices),
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(time.perf_counter() - started, 3),
    }
    logger.info("Done: %d device(s), %d findings, lowest score %d/100 in %.2fs",
                len(devices), len(findings), summary.overall_score, meta["duration_seconds"])
    return AuditResult(findings=findings, summary=summary, meta=meta)
