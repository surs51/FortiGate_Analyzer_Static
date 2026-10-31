from __future__ import annotations

from ..models import ConfigModel
from ..parser import parse_config

_FIELDS = (
    "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service",
    "action", "status", "schedule", "nat", "poolname", "logtraffic", "ssl-ssh-profile",
    "ips-sensor", "av-profile", "webfilter-profile", "dnsfilter-profile",
    "application-list", "utm-status", "profile-type", "profile-group",
    "srcaddr-negate", "dstaddr-negate", "service-negate", "internet-service",
    "internet-service-name", "users", "groups", "match-vip",
)


def _index_policies(model: ConfigModel) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for section in ("firewall policy", "firewall policy6"):
        for pol in model.objects(section, vdom=None):
            if pol.name:
                idx[f"{pol.vdom}/{pol.name}"] = {
                    f: " ".join(pol.get_list(f)) for f in _FIELDS if pol.get_list(f)}
    return idx


def _natural(s: str):
    head, _, tail = s.partition("/")
    return (head, int(tail) if tail.isdigit() else 1 << 30, tail)


def run_diff(base_text: str, other_text: str) -> str:
    a = _index_policies(parse_config(base_text))
    b = _index_policies(parse_config(other_text))
    added = sorted(set(b) - set(a), key=_natural)
    removed = sorted(set(a) - set(b), key=_natural)
    changed = [k for k in sorted(set(a) & set(b), key=_natural) if a[k] != b[k]]

    out = ["# Rule changes between the two backups", ""]
    out.append(f"Added: {len(added)}, removed: {len(removed)}, changed: {len(changed)}. "
               f"Rules are matched by VDOM and policy ID.")
    out.append("")
    if added:
        out.append("## Added rules")
        out.extend(f"- {p}" for p in added)
        out.append("")
    if removed:
        out.append("## Removed rules")
        out.extend(f"- {p}" for p in removed)
        out.append("")
    if changed:
        out.append("## Changed rules")
        for pid in changed:
            out.append(f"### {pid}")
            for key in sorted(set(a[pid]) | set(b[pid])):
                old, new = a[pid].get(key), b[pid].get(key)
                if old != new:
                    out.append(f"- `{key}`: {old or '(not set)'} → {new or '(not set)'}")
            out.append("")
    if not (added or removed or changed):
        out.append("The firewall rules are the same in both backups.")
    return "\n".join(out)
