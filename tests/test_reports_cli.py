import json
import re

import pytest

from fgaudit.cli import main
from fgaudit.reporting import ReportContext, get_reporter
from fgaudit.tools import run_diff, run_lookup


@pytest.fixture(scope="module")
def report_ctx(broken_result):
    return ReportContext(findings=broken_result.findings,
                         summary=broken_result.summary,
                         meta=broken_result.meta)


def test_json_report_valid(report_ctx):
    doc = json.loads(get_reporter("json").render(report_ctx))
    assert doc["summary"]["total_findings"] == len(report_ctx.findings)
    assert doc["metadata"]["fortios_version"] == "7.2.5"
    assert doc["metadata"]["internet_facing_interfaces"] == ["wan1"]
    assert doc["coverage"]["domains"]


def test_sarif_report_valid(report_ctx):
    doc = json.loads(get_reporter("sarif").render(report_ctx))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["results"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {res["ruleId"] for res in run["results"]} <= rule_ids


def test_csv_report_row_count(report_ctx):
    lines = get_reporter("csv").render(report_ctx).strip().splitlines()
    assert len(lines) >= len(report_ctx.findings)


def test_html_report_contains_panels(report_ctx):
    html = get_reporter("html").render(report_ctx)
    for text in ("What the internet can reach", "VIP WEB_VIP", "What this review covered",
                 "__FGAUDIT__", "NAT mode", "Internet-facing interfaces"):
        assert text in html


def test_embedded_assets_have_no_comments(report_ctx):
    html = get_reporter("html").render(report_ctx)
    assert "/*" not in html
    script = html.split("<script>")[-1]
    assert not re.search(r"^\s*//", script, re.MULTILINE)


def test_markdown_report_sections(report_ctx):
    md = get_reporter("md").render(report_ctx)
    for text in ("## Summary", "## What the internet can reach", "## What to fix, in order",
                 "POLICY_SHADOW_CONFLICT", "**What we found:**"):
        assert text in md


def test_cli_writes_all_formats(tmp_path, broken_text):
    src = tmp_path / "fw.conf"
    src.write_text(broken_text, encoding="utf-8")
    assert main([str(src), "--all-formats", "-o", str(tmp_path / "out")]) == 0
    names = {p.name for p in (tmp_path / "out").iterdir()}
    assert names == {"fw.html", "fw.json", "fw.csv", "fw.sarif", "fw.md"}


def test_cli_fail_on_gate(tmp_path, broken_text):
    src = tmp_path / "fw.conf"
    src.write_text(broken_text, encoding="utf-8")
    assert main([str(src), "--json", str(tmp_path / "r.json"), "--fail-on", "critical"]) == 1
    assert main([str(src), "--json", str(tmp_path / "r2.json"), "--min-severity", "high",
                 "--fail-on", "critical", "--vdom", "nonexistent"]) == 0


def test_cli_min_severity_recomputes_summary(tmp_path, broken_text):
    src = tmp_path / "fw.conf"
    src.write_text(broken_text, encoding="utf-8")
    out = tmp_path / "high.json"
    main([str(src), "--json", str(out), "--min-severity", "high"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["summary"]["by_severity"]["Medium"] == 0
    assert doc["metadata"]["filtered"] is True


def test_diff_detects_drift(broken_text):
    modified = broken_text.replace('set service "HTTPS"\n        set nat enable',
                                   'set service "ALL"\n        set nat enable', 1)
    modified += """
config firewall policy
    edit 99
        set name "new-rule"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
    report = run_diff(broken_text, modified)
    assert "root/99" in report
    assert "root/1" in report
    assert "Added: 1" in report
    assert "`service`: HTTPS → ALL" in report


def test_lookup_first_match(broken_text):
    out = run_lookup(broken_text, "wan1,198.51.100.7,dmz,203.0.113.10,tcp,443")
    assert 'matches policy 1 "Inbound-Web-VIP"' in out and "VIP WEB_VIP" in out
    out_zone = run_lookup(broken_text, "dmz,10.0.0.9,internal,192.168.1.10,udp,161")
    assert "matches policy 9" in out_zone
    out_deny = run_lookup(broken_text, "wan1,8.8.8.8,internal,192.168.1.10,udp,161")
    assert "implicit deny" in out_deny
    assert "Couldn't read the lookup" in run_lookup(broken_text, "nonsense")


def test_lookup_vip_ignores_rules_that_do_not_use_the_vip(broken_text):
    out = run_lookup(broken_text, "wan1,198.51.100.7,dmz,203.0.113.10,tcp,8443")
    assert "policy 1" not in out.splitlines()[0]


def test_cli_rejects_files_that_are_not_configs(tmp_path, capsys):
    src = tmp_path / "encrypted.conf"
    src.write_text("#config-version=FG100F-7.2.5-FW-build1517-230810\nnot a config\n",
                   encoding="utf-8")
    assert main([str(src), "-o", str(tmp_path)]) == 2
    assert "doesn't look like a FortiGate configuration" in capsys.readouterr().err
