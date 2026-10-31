from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .analyzers import AnalyzerConfig
from .findings import Finding, Severity
from .logging_config import configure_logging
from .reporting import ReportContext, get_reporter
from .runner import (AuditResult, __version__, find_configs, hit_counts_for, run_audit,
                     run_folder_audit)
from .scoring import build_summary
from .tools import run_diff, run_lookup

_SEV_CHOICES = ["critical", "high", "medium", "low", "informational"]
_FORMATS = ["html", "json", "csv", "sarif", "md"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fgaudit",
        description="Review a FortiGate configuration backup for security problems. "
                    "Works offline: the file is read, nothing is sent anywhere.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  fgaudit fw.conf                              writes fw.html in this folder\n"
               "  fgaudit backups/                             one report for every .conf in backups/\n"
               "  fgaudit fw.conf --all-formats -o reports/    every format into reports/\n"
               "  fgaudit fw.conf --wan wan1 wan2              say which links face the internet\n"
               "  fgaudit fw.conf --stdout-format json | jq .summary\n"
               "  fgaudit fw.conf --fail-on high               exit code 1 if anything high or worse\n"
               "  fgaudit fw.conf --hit-counts hits.json       also find rules nobody uses\n"
               "  fgaudit old.conf --diff new.conf             what changed in the rules\n"
               "  fgaudit fw.conf --lookup wan1,203.0.113.9,dmz,10.0.0.50,tcp,443\n",
    )
    p.add_argument("config", help="the FortiGate backup file (.conf), or a folder: every .conf "
                                  "in it is reviewed and they share one report")

    out = p.add_argument_group("reports")
    for fmt, label in (("html", "an HTML"), ("json", "a JSON"), ("csv", "a CSV"),
                       ("sarif", "a SARIF")):
        out.add_argument(f"--{fmt}", nargs="?", const="", metavar="PATH",
                         help=f"write {label} report (optionally to PATH)")
    out.add_argument("--md", "--markdown", dest="md", nargs="?", const="", metavar="PATH",
                     help="write a Markdown report (optionally to PATH)")
    out.add_argument("--all-formats", action="store_true", help="write all five formats")
    out.add_argument("-o", "--out-dir", default=".", metavar="DIR",
                     help="where to put the reports (default: current folder)")
    out.add_argument("--name", metavar="BASENAME",
                     help="file name for the reports, without extension (default: the "
                          "input file's or folder's name)")
    out.add_argument("--stdout-format", choices=["json", "csv", "sarif", "md"],
                     help="print one format to the screen instead of writing files")

    flt = p.add_argument_group("what to include")
    flt.add_argument("--wan", nargs="+", metavar="IFACE", default=None,
                     help="treat these interfaces as internet-facing, whatever the config says")
    flt.add_argument("--min-severity", choices=_SEV_CHOICES, default=None,
                     help="leave out findings below this severity")
    flt.add_argument("--vdom", nargs="+", metavar="VDOM", default=None,
                     help="only report findings from these VDOMs")
    flt.add_argument("--fail-on", choices=_SEV_CHOICES[:-1], default=None,
                     help="exit with code 1 if there's a finding at or above this severity "
                          "(handy in CI)")

    ext = p.add_argument_group("extra inputs (optional, read from disk)")
    ext.add_argument("--hit-counts", metavar="FILE",
                     help="JSON with rule hit counters, {policyid: hits} or "
                          "{vdom: {policyid: hits}}, to find rules that are never used. "
                          "For a folder, key it by file name: {\"fw1.conf\": {...}}")
    ext.add_argument("--psirt-feed", metavar="FILE",
                     help="JSON advisory list, {model: {version: [advisories]}}, to match "
                          "the firmware against")

    tools = p.add_argument_group("tools")
    tools.add_argument("--diff", metavar="OTHER",
                       help="compare the rules in CONFIG (older) with OTHER (newer)")
    tools.add_argument("--lookup", metavar="SPEC",
                       help="which rule would a packet hit? SPEC is "
                            "srcintf,srcip,dstintf,dstip,proto,port")

    thr = p.add_argument_group("limits")
    thr.add_argument("--excessive-policy-count", type=int, metavar="N", default=300,
                     help="flag a VDOM with at least this many rules (default 300)")
    thr.add_argument("--max-group-depth", type=int, metavar="N", default=4,
                     help="flag groups nested deeper than this (default 4)")
    thr.add_argument("--short-retention-days", type=int, metavar="N", default=30,
                     help="flag local log retention below this many days (default 30)")
    thr.add_argument("--long-admin-timeout", type=int, metavar="N", default=15,
                     help="flag admin idle timeouts above this many minutes (default 15)")
    thr.add_argument("--shadow-scan-limit", type=int, metavar="N", default=5000,
                     help="skip the shadowed-rule check above this many rules per VDOM "
                          "(default 5000)")

    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="show progress (-v) or debug output (-vv)")
    p.add_argument("--version", action="version", version=f"fgaudit {__version__}")
    return p


def _sev_value(label: str) -> int:
    return Severity.from_str(label).value


def _filter_findings(findings: list[Finding], min_severity: Optional[str],
                     vdoms: Optional[list[str]]) -> list[Finding]:
    out = findings
    if min_severity:
        threshold = _sev_value(min_severity)
        out = [f for f in out if f.severity.value <= threshold]
    if vdoms:
        wanted = set(vdoms)
        out = [f for f in out if f.vdom in wanted]
    return out


def _resolve_path(explicit: str, out_dir: Path, base: str, ext: str) -> Path:
    return Path(explicit) if explicit else out_dir / f"{base}.{ext}"


def _read_json(path: str, what: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"fgaudit: couldn't read the {what} file {path}: {exc}")


def main(argv: Optional[list[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass

    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    src = Path(args.config)
    if src.is_dir():
        if args.diff or args.lookup:
            parser.error("--diff and --lookup work on one backup file, not a folder")
        return _review_folder(args, src)
    if not src.is_file():
        parser.error(f"can't find the file or folder {src}")
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"fgaudit: couldn't read {src}: {exc}", file=sys.stderr)
        return 2

    if args.diff:
        other = Path(args.diff)
        if not other.is_file():
            parser.error(f"can't find the file to compare with: {other}")
        sys.stdout.write(run_diff(text, other.read_text(encoding="utf-8", errors="replace")))
        sys.stdout.write("\n")
        return 0

    if args.lookup:
        sys.stdout.write(run_lookup(text, args.lookup) + "\n")
        return 0

    hit_counts = _read_json(args.hit_counts, "hit counter") if args.hit_counts else None
    psirt = _read_json(args.psirt_feed, "advisory") if args.psirt_feed else None

    result = run_audit(text, wan_interfaces=args.wan, config=_analyzer_config(args),
                       source_file=src.name, hit_counts=hit_counts, psirt_feed=psirt)
    if not result.meta.get("section_count"):
        print(f"fgaudit: {src} doesn't look like a FortiGate configuration (no 'config' "
              f"blocks found). If the backup was saved with a password, save it again "
              f"without encryption.", file=sys.stderr)
        return 2
    return _report(args, result, src.stem)


def _analyzer_config(args: argparse.Namespace) -> AnalyzerConfig:
    return AnalyzerConfig(
        excessive_policy_count=args.excessive_policy_count,
        max_group_depth=args.max_group_depth,
        short_retention_days=args.short_retention_days,
        long_admin_timeout=args.long_admin_timeout,
        shadow_scan_limit=args.shadow_scan_limit,
    )


def _review_folder(args: argparse.Namespace, folder: Path) -> int:
    paths = find_configs(folder)
    if not paths:
        print(f"fgaudit: there are no .conf files in {folder}", file=sys.stderr)
        return 2

    hit_counts = _read_json(args.hit_counts, "hit counter") if args.hit_counts else None
    if hit_counts is not None and not any(hit_counts_for(hit_counts, p) for p in paths):
        raise SystemExit(f"fgaudit: for a folder, key the hit counter file by config file "
                         f"name, for example {{\"{paths[0].name}\": {{\"1\": 42}}}}. None of "
                         f"the keys in {args.hit_counts} match a .conf file in {folder}.")
    psirt = _read_json(args.psirt_feed, "advisory") if args.psirt_feed else None

    name = folder.resolve().name or "fgaudit"
    result = run_folder_audit(paths, wan_interfaces=args.wan, config=_analyzer_config(args),
                              source_dir=name, hit_counts=hit_counts, psirt_feed=psirt)
    for skip in result.meta["skipped_files"]:
        print(f"fgaudit: skipped {skip['file']}: {skip['reason']}", file=sys.stderr)
    if not result.meta["devices"]:
        print(f"fgaudit: none of the .conf files in {folder} could be reviewed. If the "
              f"backups were saved with a password, save them again without encryption.",
              file=sys.stderr)
        return 2
    return _report(args, result, name)


def _report(args: argparse.Namespace, result: AuditResult, default_name: str) -> int:
    devices = [d["device"] for d in result.meta.get("devices", [])] or None
    filtered = bool(args.min_severity or args.vdom)
    findings = _filter_findings(result.findings, args.min_severity, args.vdom)
    summary = build_summary(findings, devices=devices) if filtered else result.summary
    meta = dict(result.meta)
    if filtered:
        meta["filtered"] = True
        meta["min_severity"] = args.min_severity
        meta["vdom_filter"] = args.vdom
    ctx = ReportContext(findings=findings, summary=summary, meta=meta)

    if args.stdout_format:
        sys.stdout.write(get_reporter(args.stdout_format).render(ctx))
        if not sys.stdout.isatty():
            sys.stdout.write("\n")
        return _exit_code(findings, args.fail_on)

    base = args.name or default_name
    out_dir = Path(args.out_dir)
    wanted: dict[str, str] = {fmt: "" for fmt in _FORMATS} if args.all_formats else {}
    for fmt in _FORMATS:
        val = getattr(args, fmt)
        if val is not None:
            wanted[fmt] = val
    if not wanted:
        wanted["html"] = ""

    written = []
    for fmt, explicit in wanted.items():
        reporter = get_reporter(fmt)
        written.append(reporter.write(ctx, _resolve_path(explicit, out_dir, base, reporter.extension)))

    sev = summary.by_severity
    counts = (f"{len(findings)} findings ({sev.get('Critical', 0)} critical, "
              f"{sev.get('High', 0)} high)")
    if devices:
        print(f"fgaudit: {len(devices)} devices, {counts}, lowest device score "
              f"{summary.overall_score}/100", file=sys.stderr)
    else:
        print(f"fgaudit: {counts}, score {summary.overall_score}/100", file=sys.stderr)
    for path in written:
        print(f"  wrote {path}", file=sys.stderr)
    return _exit_code(findings, args.fail_on)


def _exit_code(findings: list[Finding], fail_on: Optional[str]) -> int:
    if not fail_on:
        return 0
    threshold = _sev_value(fail_on)
    return 1 if any(f.severity.value <= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
