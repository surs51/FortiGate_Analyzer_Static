from conftest import audit, rules_for


def test_fixture_raises_expected_rule_families(broken_rules):
    expected = {
        "POLICY_ANY_ANY_ANY",
        "POLICY_SHADOW_CONFLICT",
        "POLICY_DUPLICATE",
        "POLICY_SSL_INEFFECTIVE_PAYLOAD",
        "POLICY_LOGGING_DISABLED",
        "POLICY_DISABLED",
        "EXPOSURE_NAKED_SERVICE",
        "ZONE_INTRAZONE_ALLOW",
        "IFACE_MGMT_ON_WAN",
        "ADMIN_INSECURE_ACCESS",
        "ADMIN_NO_MFA",
        "ADMIN_NO_TRUSTED_HOST",
        "ADMIN_MULTIPLE_SUPER_ADMIN",
        "ADMIN_WEAK_PASSWORD_POLICY",
        "ADMIN_DEFAULT_NAME",
        "HARDEN_WEAK_CRYPTO",
        "HARDEN_ADMIN_TIMEOUT",
        "VPN_SSLVPN_WAN_PORTAL",
        "PROFILE_IPS_MONITOR_ONLY",
        "PROFILE_SSL_DEFAULT_CA",
        "OBJ_EMPTY_GROUP",
        "OBJ_DUPLICATE_ADDRESS",
        "OBJ_UNUSED_ADDRESS",
        "FW_VERSION_REVIEW",
        "FW_KNOWN_EXPLOITED",
        "HA_STANDALONE",
        "LOG_NO_FORTIANALYZER",
    }
    missing = expected - broken_rules
    assert not missing, f"the fixture should raise all of these; missing: {missing}"


def test_every_finding_is_fully_explained(broken_result):
    for f in broken_result.findings:
        assert f.title and f.description and f.impact and f.recommendation, f.rule_id
        assert f.risk_score >= 0
        assert f.unique_id.startswith(f.rule_id)
        assert "  " not in f.description, f.description


def test_exposure_map_artifact(broken_result):
    root = broken_result.meta["exposure_map"]["root"]
    vias = {e["via"] for e in root}
    assert {"vip:WEB_VIP", "policy:3"} <= vias
    vip_entry = next(e for e in root if e["via"] == "vip:WEB_VIP")
    assert vip_entry["naked"] is True
    assert vip_entry["service"] == "tcp/443"
    assert "203.0.113.10" in vip_entry["external"]
    assert "10.0.0.50" in vip_entry["internal"]


def test_nat_mode_artifact(broken_result):
    assert broken_result.meta["nat_mode"]["root"] == "policy-nat"


def test_firmware_meta_and_findings(broken_result):
    meta = broken_result.meta
    assert (meta["platform"], meta["fortios_version"], meta["build"]) == ("FGVM64", "7.2.5", "1517")
    assert len(rules_for(broken_result, "FW_VERSION_REVIEW")) == 1
    known = {f.affected_object.split()[0]: f for f in rules_for(broken_result, "FW_KNOWN_EXPLOITED")}
    assert known["CVE-2024-21762"].severity.label == "Critical"
    assert known["CVE-2024-23113"].severity.label == "Low"
    assert "CVE-2023-27997" not in known


def test_shadow_conflict_details(broken_result):
    hits = rules_for(broken_result, "POLICY_SHADOW_CONFLICT")
    assert len(hits) == 1
    assert hits[0].severity.label == "Critical" and "policy 5" in hits[0].affected_object


def test_psirt_feed_matching(broken_text):
    feed = {"FGVM64": {"7.2.5": ["FG-IR-23-001 heap overflow in sslvpnd"]}}
    hits = rules_for(audit(broken_text, psirt_feed=feed), "FW_PSIRT_MATCH")
    assert len(hits) == 1 and "FG-IR-23-001" in hits[0].evidence[0]
    assert not rules_for(audit(broken_text), "FW_PSIRT_MATCH")


def test_wan_override_changes_exposure(broken_text):
    res = audit(broken_text, wan_interfaces=["internal"])
    assert "internal" in {f.affected_object for f in rules_for(res, "IFACE_MGMT_ON_WAN")}


def test_intrazone_allow(broken_result):
    hits = rules_for(broken_result, "ZONE_INTRAZONE_ALLOW")
    assert len(hits) == 1 and hits[0].affected_object == "DMZ_ZONE"


def test_nat_vip_raw_ip_detected():
    res = audit("""
config system interface
    edit "wan1"
        set role wan
    next
    edit "dmz"
        set role dmz
    next
end
config firewall address
    edit "RAW_INTERNAL"
        set subnet 10.0.0.50 255.255.255.255
    next
end
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.50
        set mappedip "10.0.0.50"
    next
end
config firewall policy
    edit 1
        set name "broken-publish"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "RAW_INTERNAL"
        set service "HTTPS"
        set action accept
        set schedule "always"
    next
end
""")
    hits = rules_for(res, "NAT_VIP_RAW_IP")
    assert len(hits) == 1 and "WEB_VIP" in hits[0].description


def test_internal_snat_flagged():
    res = audit("""
config system interface
    edit "lan1"
        set role lan
    next
    edit "lan2"
        set role lan
    next
end
config firewall address
    edit "A"
        set subnet 10.1.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "east-west-nat"
        set srcintf "lan1"
        set dstintf "lan2"
        set srcaddr "A"
        set dstaddr "A"
        set service "PING"
        set action accept
        set schedule "always"
        set nat enable
    next
end
""")
    assert rules_for(res, "NAT_INTERNAL_SNAT")
