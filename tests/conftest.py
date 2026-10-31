import datetime as dt
from pathlib import Path

import pytest

from fgaudit.analyzers import AnalyzerConfig
from fgaudit.runner import run_audit

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = dt.date(2026, 9, 1)


def audit(text: str, **kwargs):
    kwargs.setdefault("config", AnalyzerConfig(today=TODAY))
    return run_audit(text, **kwargs)


def rules_for(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


@pytest.fixture(scope="session")
def broken_text() -> str:
    return (FIXTURES / "broken_config.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def broken_result(broken_text):
    return audit(broken_text, source_file="broken_config.conf")


@pytest.fixture(scope="session")
def broken_rules(broken_result) -> set[str]:
    return rule_ids(broken_result)
