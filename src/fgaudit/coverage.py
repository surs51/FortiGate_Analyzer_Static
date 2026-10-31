from __future__ import annotations

from dataclasses import dataclass, field

from .models import ConfigModel
from .object_resolver.reference_index import (
    DOMAINS,
    ReferenceIndex,
    present_unmodeled_sections,
)

ANALYZED = "analyzed"
REFERENCES_ONLY = "references-only"
NOT_MODELED = "not-modeled"
ABSENT = "absent"

_ANALYZED_DOMAINS: list[tuple[str, str, tuple[str, ...]]] = [
    ("firewall_policy", "Firewall rules", ("firewall policy", "firewall policy6")),
    ("objects", "Address and service objects",
     ("firewall address", "firewall address6", "firewall addrgrp",
      "firewall service custom", "firewall service group")),
    ("nat_vip", "NAT and published servers (VIPs)",
     ("firewall vip", "firewall vip6", "firewall ippool", "firewall central-snat-map")),
    ("admin", "Admin accounts", ("system admin", "system api-user")),
    ("auth", "Authentication servers and users", ("user ldap", "user local", "user group")),
    ("interface", "Interfaces", ("system interface",)),
    ("local_in", "Local-in policies", ("firewall local-in-policy",)),
    ("zones", "Zones", ("system zone",)),
    ("sdwan", "SD-WAN", ("system sdwan", "system virtual-wan-link")),
    ("vpn", "VPN (IPsec and SSL-VPN)",
     ("vpn ipsec phase1-interface", "vpn ipsec phase1", "vpn ssl settings")),
    ("profiles", "Security profiles",
     ("ips sensor", "antivirus profile", "webfilter profile", "dnsfilter profile",
      "application list", "firewall ssl-ssh-profile")),
    ("logging", "Logging",
     ("log fortianalyzer setting", "log fortianalyzer-cloud setting", "log syslogd setting",
      "log syslogd2 setting", "log fortiguard setting", "log disk setting",
      "log eventfilter")),
    ("high_availability", "High availability", ("system ha",)),
    ("snmp", "SNMP", ("system snmp sysinfo", "system snmp community", "system snmp user")),
    ("hardening", "System settings", ("system global", "system settings")),
]

_REFERENCE_ONLY_KEYS = [
    "proxy_policy", "security_policy", "dos_policy", "multicast_policy", "interface_policy",
    "shaping_policy", "acl", "ttl_policy", "static_route", "policy_route", "phase1_split",
    "phase2_selector", "sslvpn_portal", "ssl_exempt", "auth_rule", "exempt_list", "vipgrp",
    "sdwan_service",
]
_REFERENCE_LABELS = {d.key: d.label for d in DOMAINS}


@dataclass
class DomainCoverage:
    key: str
    label: str
    status: str
    present: bool
    count: int = 0
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.label,
            "status": self.status,
            "present": self.present,
            "count": self.count,
            "note": self.note,
        }


@dataclass
class CoverageReport:
    domains: list[DomainCoverage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    _ref_confidence: float = 0.9

    def reference_confidence(self) -> float:
        return self._ref_confidence

    def to_dict(self) -> dict:
        return {
            "domains": [d.to_dict() for d in self.domains],
            "warnings": list(self.warnings),
            "reference_confidence": round(self._ref_confidence, 3),
            "summary": {
                "analyzed": sum(1 for d in self.domains if d.status == ANALYZED and d.present),
                "references_only": sum(1 for d in self.domains
                                       if d.status == REFERENCES_ONLY and d.present),
                "not_modeled": sum(1 for d in self.domains if d.status == NOT_MODELED),
            },
        }


def build_coverage(model: ConfigModel, index: ReferenceIndex) -> CoverageReport:
    report = CoverageReport()
    section_counts: dict[str, int] = {}
    for obj in model.iter_all():
        key = obj.section.lower()
        section_counts[key] = section_counts.get(key, 0) + 1

    for key, label, probes in _ANALYZED_DOMAINS:
        count = sum(section_counts.get(p, 0) for p in probes)
        report.domains.append(DomainCoverage(
            key=key, label=label, status=ANALYZED if count else ABSENT,
            present=count > 0, count=count,
            note="checked for security issues" if count else "not in this backup",
        ))

    for key in _REFERENCE_ONLY_KEYS:
        present = key in index.domains_present
        report.domains.append(DomainCoverage(
            key=key, label=_REFERENCE_LABELS.get(key, key),
            status=REFERENCES_ONLY if present else ABSENT,
            present=present, count=index.domain_counts.get(key, 0),
            note=("read to see which objects are in use, not checked on its own"
                  if present else "not in this backup"),
        ))

    blind = present_unmodeled_sections(model)
    for label in blind:
        report.domains.append(DomainCoverage(
            key="unmodeled", label=label, status=NOT_MODELED, present=True,
            note="present, but this review doesn't read it",
        ))
        report.warnings.append(
            f"The backup contains {label}, which this review doesn't read. Objects used "
            f"only there may be reported as unused, and exposure through it isn't shown.")

    report.warnings.append(
        "Unused-object results cover rules of every kind, groups, routes, VPN and SD-WAN "
        "settings. Objects used only by FortiManager, scripts or runtime state can still "
        "show up as unused, so check before deleting.")
    report._ref_confidence = 0.6 if blind else 0.9
    return report
