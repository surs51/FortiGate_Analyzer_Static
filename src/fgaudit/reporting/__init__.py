from __future__ import annotations

from .base import ReportContext, Reporter
from .csv_reporter import CsvReporter
from .html_reporter import HtmlReporter
from .json_reporter import JsonReporter
from .markdown_reporter import MarkdownReporter
from .sarif_reporter import SarifReporter

REPORTERS: dict[str, type[Reporter]] = {
    "html": HtmlReporter,
    "json": JsonReporter,
    "csv": CsvReporter,
    "sarif": SarifReporter,
    "md": MarkdownReporter,
}


def get_reporter(fmt: str) -> Reporter:
    try:
        return REPORTERS[fmt]()
    except KeyError as exc:
        raise ValueError(
            f"Unknown report format {fmt!r}. Available: {', '.join(sorted(REPORTERS))}"
        ) from exc


__all__ = [
    "ReportContext",
    "Reporter",
    "CsvReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "SarifReporter",
    "REPORTERS",
    "get_reporter",
]
