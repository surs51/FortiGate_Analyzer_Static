from __future__ import annotations

from . import (
    admin,
    auth,
    exposure,
    firmware,
    ha,
    hardening,
    interfaces,
    logging_analyzer,
    nat,
    objects,
    policy,
    profiles,
    vpn,
    zones,
)
from .base import (
    Analyzer,
    AnalyzerConfig,
    AnalyzerContext,
    get_analyzers,
    register,
    registered_names,
)

ANALYZER_MODULES = (
    admin, auth, exposure, firmware, ha, hardening, interfaces, logging_analyzer,
    nat, objects, policy, profiles, vpn, zones,
)

__all__ = [
    "ANALYZER_MODULES",
    "Analyzer",
    "AnalyzerConfig",
    "AnalyzerContext",
    "get_analyzers",
    "register",
    "registered_names",
]
