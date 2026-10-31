from conftest import audit, rule_ids, rules_for

BASE = """
config system interface
    edit "wan1"
        set role wan
        set ip 203.0.113.1 255.255.255.0
    next
    edit "lan"
        set role lan
        set ip 192.168.1.1 255.255.255.0
    next
    edit "dmz"
        set role dmz
        set ip 10.0.0.1 255.255.255.0
    next
end
config firewall address
    edit "LAN_NET"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "DMZ_NET"
        set subnet 10.0.0.0 255.255.255.0
    next
    edit "ONE_HOST"
        set subnet 10.0.0.50 255.255.255.255
    next
end
"""


def policy(pid, **settings):
    lines = [f"    edit {pid}"]
    defaults = {"srcintf": '"lan"', "dstintf": '"dmz"', "srcaddr": '"LAN_NET"',
                "dstaddr": '"DMZ_NET"', "service": '"ALL"', "action": "accept",
                "schedule": '"always"'}
    defaults.update(settings)
    for key, value in defaults.items():
        if value is not None:
            lines.append(f"        set {key.replace('_', '-')} {value}")
    lines.append("    next")
    return "\n".join(lines)


def policies(*items):
    return "config firewall policy\n" + "\n".join(items) + "\nend\n"


def test_shadow_conflict_deny_under_accept():
    res = audit(BASE + policies(
        policy(1, name='"allow-broad"'),
        policy(2, name='"deny-host"', dstaddr='"ONE_HOST"', service='"SSH"', action="deny")))
    hits = rules_for(res, "POLICY_SHADOW_CONFLICT")
    assert len(hits) == 1
    assert hits[0].severity.label == "Critical"
    assert "policy 2" in hits[0].affected_object
    assert "is allowed" in hits[0].description


def test_shadow_profiles_lost():
    res = audit(BASE + """
config ips sensor
    edit "block-things"
        config entries
            edit 1
                set action block
            next
        end
    next
end
""" + policies(
        policy(1, name='"broad-no-profiles"'),
        policy(2, name='"narrow-with-ips"', dstaddr='"ONE_HOST"', service='"HTTPS"',
               ips_sensor='"block-things"')))
    hits = rules_for(res, "POLICY_SHADOW_PROFILES")
    assert len(hits) == 1 and hits[0].severity.label == "High"
    assert not rules_for(res, "POLICY_SHADOW_CONFLICT")


def test_redundant_shadow_same_treatment_not_duplicate():
    res = audit(BASE + policies(
        policy(1, name='"broad"'),
        policy(2, name='"narrow-same"', dstaddr='"ONE_HOST"', service='"HTTPS"')))
    assert len(rules_for(res, "POLICY_SHADOWED")) == 1
    assert not rules_for(res, "POLICY_DUPLICATE")


def test_strict_duplicate_reported_once_not_as_shadow():
    res = audit(BASE + policies(
        policy(1, name='"a"', dstaddr='"ONE_HOST"', service='"HTTPS"'),
        policy(2, name='"b"', dstaddr='"ONE_HOST"', service='"HTTPS"')))
    assert len(rules_for(res, "POLICY_DUPLICATE")) == 1
    assert not rules_for(res, "POLICY_SHADOWED")
    assert not rules_for(res, "POLICY_SHADOW_PROFILES")


def test_near_duplicate_different_logging():
    res = audit(BASE + policies(
        policy(1, name='"a"', dstaddr='"ONE_HOST"', service='"HTTPS"', logtraffic="all"),
        policy(2, name='"b"', dstaddr='"ONE_HOST"', service='"HTTPS"', logtraffic="disable")))
    hits = rules_for(res, "POLICY_NEAR_DUPLICATE")
    assert len(hits) == 1 and "logging" in hits[0].description


def test_deny_partial_overlap():
    res = audit(BASE + """
config firewall address
    edit "HALF_NET"
        set subnet 10.0.0.0 255.255.255.128
    next
end
""" + policies(
        policy(1, name='"allow-half"', dstaddr='"HALF_NET"'),
        policy(2, name='"deny-whole"', service='"SSH"', action="deny")))
    assert len(rules_for(res, "POLICY_DENY_PARTIAL_OVERLAP")) == 1


def test_group_resolving_to_all_is_any_any_any():
    res = audit(BASE + """
config firewall address
    edit "Internal_Server"
        set subnet 0.0.0.0 0.0.0.0
    next
end
config firewall addrgrp
    edit "Safe_Group"
        set member "Internal_Server"
    next
end
""" + policies(policy(1, name='"looks-narrow"', srcintf='"wan1"',
                      srcaddr='"Safe_Group"', dstaddr='"Safe_Group"')))
    hits = rules_for(res, "POLICY_ANY_ANY_ANY")
    assert len(hits) == 1 and hits[0].severity.label == "Critical"


def test_negated_source_is_treated_as_broad():
    res = audit(BASE + policies(
        policy(1, name='"everyone-but-lan"', srcintf='"lan"', dstintf='"wan1"',
               srcaddr='"LAN_NET"', srcaddr_negate="enable", dstaddr='"all"')))
    assert rules_for(res, "POLICY_ANY_ANY_ANY")


def test_internet_service_deny_below_allow_all_is_a_conflict():
    res = audit(BASE + policies(
        policy(1, name='"out"', dstintf='"wan1"', dstaddr='"all"', nat="enable"),
        policy(2, name='"block-tor"', dstintf='"wan1"', dstaddr=None, service=None,
               internet_service="enable", internet_service_name='"Tor-Exit.Node"',
               action="deny")))
    hits = rules_for(res, "POLICY_SHADOW_CONFLICT")
    assert len(hits) == 1 and "policy 2" in hits[0].affected_object


def test_identity_rule_does_not_shadow_open_rule():
    res = audit(BASE + policies(
        policy(1, name='"users-only"', groups='"Staff"'),
        policy(2, name='"then-block"', dstaddr='"ONE_HOST"', service='"SSH"', action="deny")))
    assert not rules_for(res, "POLICY_SHADOW_CONFLICT")


VIP = """
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.50
        set extintf "wan1"
        set portforward enable
        set extport 443
        set mappedport 443
        set mappedip "10.0.0.50"
    next
end
"""


def test_port_forward_vip_limits_what_service_all_exposes():
    res = audit(BASE + VIP + policies(
        policy(1, name='"publish"', srcintf='"wan1"', srcaddr='"all"', dstaddr='"WEB_VIP"',
               service='"ALL"', utm_status="enable", ips_sensor='"default"',
               ssl_ssh_profile='"deep-inspection"')))
    assert not rules_for(res, "POLICY_WAN_EXPOSURE")
    hits = rules_for(res, "POLICY_SERVICE_ALL")
    assert len(hits) == 1 and hits[0].severity.label == "Low"
    assert "tcp/443" in hits[0].description


def test_deny_without_match_vip_does_not_shadow_vip_rule():
    res = audit(BASE + VIP + """
config firewall address
    edit "BAD_GUYS"
        set subnet 198.51.100.0 255.255.255.0
    next
end
""" + policies(
        policy(1, name='"block-bad"', srcintf='"wan1"', srcaddr='"BAD_GUYS"', dstaddr='"all"',
               action="deny"),
        policy(2, name='"publish"', srcintf='"wan1"', srcaddr='"all"', dstaddr='"WEB_VIP"',
               service='"HTTPS"')))
    assert not rules_for(res, "POLICY_SHADOW_CONFLICT")
    hits = rules_for(res, "POLICY_DENY_SKIPS_VIP")
    assert len(hits) == 1 and "WEB_VIP" in hits[0].description


def test_match_vip_deny_is_respected():
    res = audit(BASE + VIP + policies(
        policy(1, name='"block-all-in"', srcintf='"wan1"', srcaddr='"all"', dstaddr='"all"',
               action="deny", match_vip="enable"),
        policy(2, name='"publish"', srcintf='"wan1"', srcaddr='"all"', dstaddr='"WEB_VIP"',
               service='"HTTPS"')))
    assert not rules_for(res, "POLICY_DENY_SKIPS_VIP")
    assert len(rules_for(res, "POLICY_SHADOW_CONFLICT")) == 1


def test_ssl_depth_only_matters_for_encrypted_services():
    res = audit(BASE + policies(
        policy(1, name='"web-plain"', dstaddr='"ONE_HOST"', service='"HTTP"',
               utm_status="enable", av_profile='"default"',
               ssl_ssh_profile='"certificate-inspection"'),
        policy(2, name='"web-tls"', dstaddr='"DMZ_NET"', service='"HTTPS"',
               utm_status="enable", av_profile='"default"',
               ssl_ssh_profile='"certificate-inspection"')))
    hits = rules_for(res, "POLICY_SSL_INEFFECTIVE_PAYLOAD")
    assert [h.affected_object for h in hits] == ['policy 2 "web-tls"']


def test_remote_access_rule_that_opens_everything():
    res = audit(BASE + policies(
        policy(1, name='"vpn-users"', srcintf='"ssl.root"', srcaddr='"all"', dstaddr='"all"',
               groups='"VPN"')))
    hits = rules_for(res, "VPN_BROAD_ACCESS")
    assert len(hits) == 1 and hits[0].severity.label == "High"
    assert not rules_for(res, "POLICY_ANY_ANY_ANY")


def test_zero_hit_rules_with_counters():
    cfg = BASE + policies(
        policy(1, name='"used"', service='"HTTPS"'),
        policy(2, name='"never-used"', dstaddr='"ONE_HOST"', service='"SSH"'))
    res = audit(cfg, hit_counts={"1": 5000, "2": 0})
    hits = rules_for(res, "POLICY_ZERO_HIT")
    assert len(hits) == 1 and "2" in hits[0].evidence[0]
    assert not rules_for(audit(cfg), "POLICY_ZERO_HIT")


def test_expired_schedule_in_both_quoting_styles():
    for end in ("17:00 2020/12/31", '"17:00 2020/12/31"'):
        res = audit(BASE + f"""
config firewall schedule onetime
    edit "migration-window"
        set start "08:00 2020/01/01"
        set end {end}
    next
end
""" + policies(policy(1, name='"temp"', service='"HTTPS"', schedule='"migration-window"')))
        hits = rules_for(res, "POLICY_EXPIRED_SCHEDULE")
        assert len(hits) == 1 and "2020-12-31" in hits[0].description


def test_hygiene_aggregated_not_flooding():
    body = [policy(i, dstaddr='"ONE_HOST"', service='"PING"') for i in range(1, 21)]
    res = audit(BASE + policies(*body))
    assert len(rules_for(res, "POLICY_NO_NAME")) == 1
    assert len(rules_for(res, "POLICY_NO_COMMENT")) == 1
    assert "20 rules" in rules_for(res, "POLICY_NO_NAME")[0].description


def test_rule_that_matches_nothing_is_ignored():
    res = audit(BASE + policies(
        policy(1, name='"broad"'),
        policy(2, name='"nothing"', dstaddr='"none"', action="deny")))
    assert "POLICY_SHADOW_CONFLICT" not in rule_ids(res)
