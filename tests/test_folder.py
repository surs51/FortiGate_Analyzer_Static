import json

import pytest

from fgaudit.analyzers import AnalyzerConfig
from fgaudit.cli import main
from fgaudit.reporting import ReportContext, get_reporter
from fgaudit.runner import find_configs, run_folder_audit

from conftest import TODAY

ENCRYPTED = "#config-version=FG100F-7.2.5-FW-build1517-230810:opmode=0\nENCRYPTEDDATA==\n"


def _branch(text: str) -> str:
    start = text.index("config firewall policy\n")
    end = text.index("\nend\n", start) + len("\nend\n")
    return text[:start].replace('set hostname "fgt-demo"', 'set hostname "branch-01"') + text[end:]


@pytest.fixture()
def fleet_dir(tmp_path, broken_text):
    d = tmp_path / "sites"
    d.mkdir()
    (d / "hq.conf").write_text(broken_text, encoding="utf-8")
    (d / "Branch.CONF").write_text(_branch(broken_text), encoding="utf-8")
    (d / "locked.conf").write_text(ENCRYPTED, encoding="utf-8")
    (d / "notes.txt").write_text("not a config", encoding="utf-8")
    return d


@pytest.fixture()
def fleet_result(fleet_dir):
    return run_folder_audit(find_configs(fleet_dir), config=AnalyzerConfig(today=TODAY),
                            source_dir="sites")


def test_find_configs_takes_only_conf_files(fleet_dir):
    assert [p.name for p in find_configs(fleet_dir)] == ["Branch.CONF", "hq.conf", "locked.conf"]


def test_folder_audit_tags_findings_and_skips_non_configs(fleet_result):
    meta = fleet_result.meta
    assert [d["device"] for d in meta["devices"]] == ["Branch.CONF", "hq.conf"]
    assert [d["hostname"] for d in meta["devices"]] == ["branch-01", "fgt-demo"]
    assert [s["file"] for s in meta["skipped_files"]] == ["locked.conf"]
    assert {f.device for f in fleet_result.findings} == {"Branch.CONF", "hq.conf"}
    ids = [f.unique_id for f in fleet_result.findings]
    assert len(ids) == len(set(ids))


def test_folder_score_is_the_weakest_device(fleet_result, broken_result):
    by_device = fleet_result.summary.by_device
    assert by_device["hq.conf"]["overall_score"] == broken_result.summary.overall_score
    assert by_device["hq.conf"]["total_findings"] == len(broken_result.findings)
    assert fleet_result.summary.overall_score == min(d["overall_score"]
                                                     for d in by_device.values())
    assert fleet_result.summary.total_findings == len(fleet_result.findings)


def test_single_file_findings_have_no_device(broken_result):
    d = broken_result.findings[0].to_dict()
    assert "device" not in d
    assert "by_device" not in broken_result.summary.to_dict()


def test_folder_reports_show_devices(fleet_result):
    ctx = ReportContext(findings=fleet_result.findings, summary=fleet_result.summary,
                        meta=fleet_result.meta)
    html = get_reporter("html").render(ctx)
    for text in ('id="devices-section"', 'id="device-select"', "branch-01",
                 "locked.conf", "Lowest device score", '"devices":["Branch.CONF","hq.conf"]'):
        assert text in html
    md = get_reporter("md").render(ctx)
    for text in ("## Devices", "### `hq.conf`", "device `Branch.CONF`", "`locked.conf`"):
        assert text in md
    csv_head = get_reporter("csv").render(ctx).splitlines()[0]
    assert csv_head.startswith("device,")
    sarif = json.loads(get_reporter("sarif").render(ctx))
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]}
    assert uris == {"Branch.CONF", "hq.conf"}


def test_cli_folder_writes_one_report(fleet_dir, tmp_path, capsys):
    out = tmp_path / "out"
    assert main([str(fleet_dir), "--json", "--md", "-o", str(out)]) == 0
    assert {p.name for p in out.iterdir()} == {"sites.json", "sites.md"}
    doc = json.loads((out / "sites.json").read_text(encoding="utf-8"))
    assert doc["metadata"]["device_count"] == 2
    assert set(doc["summary"]["by_device"]) == {"Branch.CONF", "hq.conf"}
    assert all(f["device"] in ("Branch.CONF", "hq.conf") for f in doc["findings"])
    err = capsys.readouterr().err
    assert "skipped locked.conf" in err and "2 devices" in err


def test_cli_folder_filters_recompute_device_scores(fleet_dir, tmp_path):
    out = tmp_path / "crit.json"
    main([str(fleet_dir), "--json", str(out), "--min-severity", "critical"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    for dev in doc["summary"]["by_device"].values():
        assert dev["by_severity"]["High"] == 0
    assert doc["summary"]["total_findings"] == sum(
        d["total_findings"] for d in doc["summary"]["by_device"].values())


def test_cli_folder_hit_counts_keyed_by_file(fleet_dir, tmp_path):
    hits = tmp_path / "hits.json"
    hits.write_text(json.dumps({"hq.conf": {"2": 0}}), encoding="utf-8")
    out = tmp_path / "hits-report.json"
    assert main([str(fleet_dir), "--json", str(out), "--hit-counts", str(hits)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    zero = [f for f in doc["findings"] if f["rule_id"] == "POLICY_ZERO_HIT"]
    assert [f["device"] for f in zero] == ["hq.conf"]

    hits.write_text(json.dumps({"2": 0}), encoding="utf-8")
    with pytest.raises(SystemExit, match="key the hit counter file by config file name"):
        main([str(fleet_dir), "--json", str(out), "--hit-counts", str(hits)])


def test_cli_folder_without_usable_configs(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main([str(empty)]) == 2
    assert "no .conf files" in capsys.readouterr().err

    (empty / "locked.conf").write_text(ENCRYPTED, encoding="utf-8")
    assert main([str(empty), "-o", str(tmp_path)]) == 2
    assert "none of the .conf files" in capsys.readouterr().err


def test_cli_folder_rejects_single_file_tools(fleet_dir):
    with pytest.raises(SystemExit) as exc:
        main([str(fleet_dir), "--lookup", "wan1,1.1.1.1,dmz,10.0.0.1,tcp,443"])
    assert exc.value.code == 2
