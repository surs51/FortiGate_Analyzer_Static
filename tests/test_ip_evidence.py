import csv
import io
import json
import re

import pytest

from fgaudit.ip_evidence import parse_literal
from fgaudit.reporting import ReportContext, get_reporter

from conftest import audit, rules_for

EDGE = """#config-version=FG100F-7.2.5-FW-build1517-230810:opmode=0:vdom=0
config system interface
    edit "wan1"
        set mode dhcp
        set allowaccess ping https ssh
        set role wan
    next
    edit "port2"
        set ip 10.1.1.1 255.255.255.0
        config secondaryip
            edit 1
                set ip 10.1.2.1 255.255.255.0
            next
        end
        config ipv6
            set ip6-address 2001:db8:1::1/64
        end
    next
    edit "port3"
        set ip 10.1.3.1 255.255.255.0
    next
end
config system zone
    edit "LAN_ZONE"
        set interface "port2" "port3"
    next
end
config firewall address
    edit "H1"
        set subnet 10.1.1.10 255.255.255.255
    next
    edit "H2"
        set subnet 10.1.1.11 255.255.255.255
    next
    edit "SITE"
        set type fqdn
        set fqdn "www.example.com"
    next
end
config firewall addrgrp
    edit "G"
        set member "H1" "H2"
        set exclude enable
        set exclude-member "H2"
    next
end
config firewall policy
    edit 1
        set srcintf "LAN_ZONE"
        set dstintf "wan1"
        set srcaddr "G"
        set srcaddr-negate enable
        set dstaddr "SITE" "MISSING_OBJ"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
config vpn ipsec phase1-interface
    edit "tun1"
        set interface "port3"
        set remote-gw 198.51.100.77
        set ike-version 1
    next
end
config vpn ipsec phase2-interface
    edit "tun1-p2"
        set phase1name "tun1"
        set pfs disable
        set src-subnet 10.1.1.0 255.255.255.0
        set dst-subnet 172.20.0.0 255.255.0.0
    next
end
config user ldap
    edit "AD"
        set server "dc1.corp.local"
        set secure disable
    next
end
"""


def _ref(finding, setting, source_part=""):
    for ref in finding.ips:
        if ref.setting == setting and source_part in ref.source:
            return ref
    raise AssertionError(f"no {setting} ref from {source_part!r} in {finding.ips}")


@pytest.mark.parametrize("tokens,expected", [
    (["203.0.113.2", "255.255.255.0"], ["203.0.113.2/24"]),
    (["0.0.0.0", "0.0.0.0"], ["0.0.0.0/0"]),
    (["10.0.0.0/8"], ["10.0.0.0/8"]),
    (["10.0.0.5-10.0.0.9"], ["10.0.0.5-10.0.0.9"]),
    (["10.0.0.1", "10.0.0.2"], ["10.0.0.1", "10.0.0.2"]),
    (["2001:db8::1/64"], ["2001:db8::1/64"]),
    (["dc1.corp.local"], []),
    (["my-net"], []),
])
def test_parse_literal(tokens, expected):
    assert parse_literal(tokens) == expected


def test_every_ip_points_at_a_real_set_line(broken_result, broken_text):
    lines = broken_text.splitlines()
    checked = 0
    for f in broken_result.findings:
        for ref in f.ips:
            assert ref.line, ref
            block = lines[ref.line - 1:ref.line + 40]
            wanted = f"set {ref.setting} "
            assert any(l.strip().startswith(wanted) for l in block), (f.rule_id, ref)
            checked += 1
    assert checked > 50


def test_interface_finding_carries_its_address(broken_result):
    f = rules_for(broken_result, "IFACE_MGMT_ON_WAN")[0]
    ref = _ref(f, "ip", "system interface wan1")
    assert ref.ips == ("203.0.113.10/24",)
    assert ref.written == "203.0.113.10 255.255.255.0" and ref.line == 30


def test_exposure_finding_shows_the_vip_mapping(broken_result):
    f = [x for x in rules_for(broken_result, "EXPOSURE_NAKED_SERVICE") if "VIP" in x.affected_object][0]
    assert _ref(f, "extip", "firewall vip WEB_VIP").ips == ("203.0.113.10",)
    assert _ref(f, "mappedip", "firewall vip WEB_VIP").ips == ("10.0.0.50",)
    assert _ref(f, "srcaddr", "firewall policy 1").ips == ("0.0.0.0/0",)


def test_exploited_cve_points_at_the_listening_interface(broken_result):
    f = [x for x in rules_for(broken_result, "FW_KNOWN_EXPLOITED") if "21762" in x.affected_object][0]
    assert _ref(f, "ip", "system interface wan1").ips == ("203.0.113.10/24",)
    assert "config vpn ssl settings (line 250)" in f.evidence


def test_policy_addresses_are_resolved_through_objects(broken_result):
    f = rules_for(broken_result, "POLICY_SHADOW_CONFLICT")[0]
    src = _ref(f, "srcaddr", "firewall policy 5")
    assert src.written == "PARTNER_NET" and src.ips == ("198.51.100.0/24",)
    assert _ref(f, "dstaddr", "firewall policy 4").ips == ("10.0.0.0/24",)


def test_edge_cases_only_report_what_the_config_says():
    result = audit(EDGE)
    pol = [f for f in result.findings if f.affected_object == "policy 1"][0]
    src = _ref(pol, "srcaddr", "firewall policy 1")
    assert src.ips == ("10.1.1.10/32",)
    assert "srcaddr-negate is enabled" in src.note
    dst = _ref(pol, "dstaddr", "firewall policy 1")
    assert dst.ips == ("fqdn:www.example.com", "unknown object MISSING_OBJ")
    assert _ref(pol, "ip", "system interface port2 > secondaryip 1").ips == ("10.1.2.1/24",)
    assert _ref(pol, "ip6-address", "port2 > ipv6").ips == ("2001:db8:1::1/64",)
    assert _ref(pol, "ip", "system interface port3").ips == ("10.1.3.1/24",)
    dhcp = _ref(pol, "mode", "system interface wan1")
    assert dhcp.ips == () and "assigned by DHCP" in dhcp.note

    p2 = rules_for(result, "VPN_PHASE2_WEAK")[0]
    assert _ref(p2, "dst-subnet").ips == ("172.20.0.0/16",)
    assert _ref(p2, "remote-gw", "phase1-interface tun1").ips == ("198.51.100.77",)
    assert _ref(p2, "ip", "system interface port3").ips == ("10.1.3.1/24",)

    ldap = rules_for(result, "AUTH_LDAP_CLEARTEXT")[0]
    server = _ref(ldap, "server", "user ldap AD")
    assert server.ips == () and server.written == "dc1.corp.local" and "not an IP" in server.note


def test_reports_include_ips(broken_result):
    ctx = ReportContext(findings=broken_result.findings, summary=broken_result.summary,
                        meta=broken_result.meta)
    doc = json.loads(get_reporter("json").render(ctx))
    mgmt = [f for f in doc["findings"] if f["rule_id"] == "IFACE_MGMT_ON_WAN"][0]
    assert mgmt["ips"][0] == {"source": "system interface wan1", "line": 30, "setting": "ip",
                              "written": "203.0.113.10 255.255.255.0",
                              "ips": ["203.0.113.10/24"]}
    rows = list(csv.DictReader(io.StringIO(get_reporter("csv").render(ctx))))
    mgmt_row = [r for r in rows if r["rule_id"] == "IFACE_MGMT_ON_WAN"][0]
    assert mgmt_row["ips"] == ("203.0.113.10/24 (from system interface wan1, line 30: "
                               "set ip 203.0.113.10 255.255.255.0)")
    assert "IP addresses from the config:" in get_reporter("md").render(ctx)
    sarif = json.loads(get_reporter("sarif").render(ctx))
    assert any(r["properties"].get("ips") for r in sarif["runs"][0]["results"])


def test_html_payload_is_deduplicated(broken_result):
    ctx = ReportContext(findings=broken_result.findings, summary=broken_result.summary,
                        meta=broken_result.meta)
    html = get_reporter("html").render(ctx)
    raw = re.search(r'<script type="application/json" id="__FGAUDIT__">(.*?)</script>',
                    html, re.S).group(1)
    assert "<" not in raw
    data = json.loads(raw)
    assert len(data["findings"]) == len(broken_result.findings)
    assert len(data["texts"]) == len({f.rule_id for f in broken_result.findings})
    distinct = {r for f in broken_result.findings for r in f.ips}
    assert len(data["ips"]) == len(distinct)
    wan = [r for r in data["ips"] if r[0] == "system interface wan1" and r[2] == "ip"]
    assert wan == [["system interface wan1", 30, "ip", "203.0.113.10 255.255.255.0",
                    ["203.0.113.10/24"], 0, ""]]
