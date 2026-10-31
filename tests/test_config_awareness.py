from fgaudit.findings import Severity
from fgaudit.object_resolver import ObjectResolver
from fgaudit.parser import parse_config

from conftest import audit, rule_ids, rules_for

HEADER_72 = "#config-version=FG100F-7.2.5-FW-build1517-230810:opmode=0:vdom=0\n"


def resolver(text: str) -> ObjectResolver:
    return ObjectResolver(parse_config(text))


def test_explicit_default_route_marks_interface_as_wan():
    r = resolver("""
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.1
        set device "port7"
    next
end
""")
    assert r.interface_is_internet_facing("port7") == (True, "high")
    assert "default route" in r.wan_reason("port7")


def test_default_route_through_sdwan_zone_marks_members():
    r = resolver("""
config system sdwan
    set status enable
    config zone
        edit "ISP"
        next
    end
    config members
        edit 1
            set interface "x1"
            set zone "ISP"
        next
    end
end
config router static
    edit 1
        set sdwan-zone "ISP"
    next
end
""")
    assert r.interface_is_internet_facing("x1") == (True, "high")
    assert {"x1", "ISP"} <= r.internet_facing_interfaces


def test_dhcp_and_pppoe_uplinks_are_wan():
    r = resolver("""
config system interface
    edit "a"
        set mode dhcp
    next
    edit "b"
        set mode pppoe
    next
    edit "c"
        set mode dhcp
        set defaultgw disable
    next
end
""")
    assert r.interface_is_internet_facing("a")[0]
    assert r.interface_is_internet_facing("b")[0]
    assert not r.interface_is_internet_facing("c")[0]


def test_name_guess_only_without_real_signals():
    guess = resolver("""
config system interface
    edit "wan-backup"
        set ip 10.0.0.1 255.255.255.0
    next
end
""")
    assert guess.interface_is_internet_facing("wan-backup") == (True, "low")
    real = resolver("""
config system interface
    edit "port1"
        set role wan
    next
    edit "wan-backup"
        set ip 10.0.0.1 255.255.255.0
    next
end
""")
    assert not real.interface_is_internet_facing("wan-backup")[0]


def test_dmz_with_public_addresses_is_not_wan():
    r = resolver("""
config system interface
    edit "dmz"
        set role dmz
        set ip 8.8.4.1 255.255.255.0
    next
end
""")
    assert not r.interface_is_internet_facing("dmz")[0]


MGMT = """
config system interface
    edit "wan1"
        set role wan
        set ip 203.0.113.2 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall address
    edit "MGMT_NET"
        set subnet 198.51.100.0 255.255.255.0
    next
end
"""


def test_management_on_wan_without_local_in_is_critical():
    hits = rules_for(audit(MGMT), "IFACE_MGMT_ON_WAN")
    assert len(hits) == 1 and hits[0].severity is Severity.CRITICAL
    assert "from any address" in hits[0].description


def test_local_in_policy_restricting_management_lowers_severity():
    res = audit(MGMT + """
config firewall local-in-policy
    edit 1
        set intf "wan1"
        set srcaddr "MGMT_NET"
        set dstaddr "all"
        set service "HTTPS" "SSH"
        set action accept
        set schedule "always"
    next
    edit 2
        set intf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS" "SSH"
        set schedule "always"
    next
end
""")
    hits = rules_for(res, "IFACE_MGMT_ON_WAN")
    assert len(hits) == 1 and hits[0].severity is Severity.MEDIUM
    assert "198.51.100.0/24" in hits[0].description


def test_local_in_deny_on_all_hides_the_listener():
    res = audit(MGMT + """
config firewall local-in-policy
    edit 1
        set intf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
    next
end
""")
    assert "IFACE_MGMT_ON_WAN" not in rule_ids(res)


def test_api_user_nested_trusthost_is_respected():
    res = audit("""
config system api-user
    edit "automation"
        set accprofile "read_only"
        config trusthost
            edit 1
                set ipv4-trustedhost 10.10.10.0 255.255.255.0
            next
        end
    next
    edit "lazy"
        set accprofile "super_admin"
    next
end
""")
    hits = rules_for(res, "ADMIN_API_EXCESSIVE_PRIV")
    assert [h.affected_object for h in hits] == ["lazy"]
    assert hits[0].severity is Severity.HIGH


def test_wildcard_admin_and_remote_mfa_confidence():
    res = audit("""
config system admin
    edit "radius-admins"
        set remote-auth enable
        set remote-group "NetOps"
        set wildcard enable
        set accprofile "super_admin"
        set trusthost1 10.0.0.0 255.0.0.0
    next
end
""")
    wildcard = rules_for(res, "ADMIN_WILDCARD_REMOTE")
    assert len(wildcard) == 1 and wildcard[0].severity is Severity.HIGH
    mfa = rules_for(res, "ADMIN_NO_MFA")
    assert len(mfa) == 1 and mfa[0].confidence.value == "low"
    assert "ADMIN_LOCAL_ACCOUNT" not in rule_ids(res)


def test_http_admin_with_redirect_is_medium():
    res = audit("""
config system interface
    edit "lan"
        set role lan
        set allowaccess https http
    next
end
""")
    hits = rules_for(res, "ADMIN_INSECURE_ACCESS")
    assert len(hits) == 1 and hits[0].severity is Severity.MEDIUM


def test_central_nat_mode_uses_mapped_addresses():
    cfg = """
config system settings
    set central-nat enable
end
config system interface
    edit "wan1"
        set role wan
    next
    edit "dmz"
        set role dmz
    next
end
config firewall vip
    edit "WEB"
        set extip 203.0.113.50
        set extintf "wan1"
        set mappedip "10.0.0.50"
    next
end
config firewall address
    edit "WEB_REAL"
        set subnet 10.0.0.50 255.255.255.255
    next
end
config firewall policy
    edit 1
        set name "publish"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "WEB_REAL"
        set service "HTTPS"
        set action accept
        set schedule "always"
    next
end
"""
    res = audit(cfg)
    assert res.meta["nat_mode"]["root"] == "central-nat"
    assert "NAT_VIP_RAW_IP" not in rule_ids(res)
    assert "OBJ_ORPHAN_VIP" not in rule_ids(res)
    entry = res.meta["exposure_map"]["root"][0]
    assert entry["via"] == "vip:WEB" and entry["policy"] == "1"


def test_internal_vip_is_not_in_the_internet_map():
    res = audit("""
config system interface
    edit "wan1"
        set role wan
    next
    edit "lan"
        set role lan
    next
end
config firewall vip
    edit "INTERNAL_LB"
        set extip 10.20.0.10
        set extintf "lan"
        set mappedip "10.30.0.10"
    next
end
""")
    assert not res.meta["exposure_map"]


def test_inbound_rule_blocked_by_earlier_deny_is_not_exposed():
    res = audit("""
config system interface
    edit "wan1"
        set role wan
    next
    edit "dmz"
        set role dmz
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
        set schedule "always"
    next
    edit 2
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "all"
        set service "SSH"
        set action accept
        set schedule "always"
    next
end
""")
    assert not res.meta["exposure_map"]
    assert "EXPOSURE_NAKED_SERVICE" not in rule_ids(res)


def test_private_data_encryption_only_matters_with_secrets():
    base = "config system global\n    set hostname fw\nend\n"
    assert "HARDEN_PRIVATE_DATA_ENCRYPTION" not in rule_ids(audit(base))
    secret = base + """
config vpn ipsec phase1-interface
    edit "to-hq"
        set ike-version 2
        set psksecret ENC c2VjcmV0c2VjcmV0
    next
end
"""
    assert "HARDEN_PRIVATE_DATA_ENCRYPTION" in rule_ids(audit(secret))
    protected = secret.replace("set hostname fw", "set private-data-encryption enable")
    assert "HARDEN_PRIVATE_DATA_ENCRYPTION" not in rule_ids(audit(protected))


def test_snmp_checks_only_when_agent_is_on_and_reachable():
    snmp = """
config system snmp community
    edit 1
        set name "public"
    next
end
"""
    listening = """
config system interface
    edit "lan"
        set role lan
        set allowaccess snmp
    next
end
"""
    agent = "config system snmp sysinfo\n    set status enable\nend\n"
    assert "HARDEN_SNMP_WEAK" not in rule_ids(audit(snmp + listening))
    hits = rules_for(audit(snmp + listening + agent), "HARDEN_SNMP_WEAK")
    assert len(hits) == 1 and hits[0].severity is Severity.HIGH
    unneeded = rules_for(audit(snmp + listening), "IFACE_UNNEEDED_PROTOCOL")
    assert unneeded and "SNMP agent is off" in unneeded[0].description


def test_asymroute_and_antispoof():
    res = audit("""
config system settings
    set asymroute enable
end
config system interface
    edit "wan1"
        set role wan
        set src-check disable
    next
end
""")
    assert "HARDEN_ASYMROUTE" in rule_ids(res)
    spoof = rules_for(res, "IFACE_NO_ANTISPOOF")
    assert len(spoof) == 1 and spoof[0].severity is Severity.MEDIUM


def test_ipsec_aggressive_mode_and_weak_phase2():
    res = audit("""
config vpn ipsec phase1-interface
    edit "branch"
        set type dynamic
        set mode aggressive
        set proposal aes128-sha1 3des-md5
        set dhgrp 2 14
    next
end
config vpn ipsec phase2-interface
    edit "branch-p2"
        set phase1name "branch"
        set pfs disable
    next
end
""")
    ids = rule_ids(res)
    assert {"VPN_IKEV1", "VPN_AGGRESSIVE_MODE", "VPN_WEAK_DH", "VPN_WEAK_CIPHER",
            "VPN_PHASE2_WEAK"} <= ids
    cipher = rules_for(res, "VPN_WEAK_CIPHER")[0]
    assert "3DES" in cipher.description and "MD5" in cipher.description


def test_sslvpn_tls_default_depends_on_version():
    body = """
config system interface
    edit "wan1"
        set role wan
    next
end
config vpn ssl settings
    set source-interface "wan1"
    set source-address "HOME"
end
"""
    old = audit("#config-version=FGT60E-6.0.9-FW-build0335-200101:opmode=0:vdom=0\n" + body)
    new = audit(HEADER_72 + body)
    assert "VPN_SSL_WEAK_TLS" in rule_ids(old)
    assert "VPN_SSL_WEAK_TLS" not in rule_ids(new)
    portal = rules_for(new, "VPN_SSLVPN_WAN_PORTAL")[0]
    assert portal.severity is Severity.MEDIUM
    assert "VPN_SSL_DEFAULT_CERT" in rule_ids(new)


def test_end_of_support_and_patchless_versions():
    eos = audit("#config-version=FGT60E-6.4.15-FW-build2095-240101:opmode=0:vdom=0\n")
    assert "FW_END_OF_SUPPORT" in rule_ids(eos)
    current = audit(HEADER_72)
    assert "FW_END_OF_SUPPORT" not in rule_ids(current)
    old_style = audit("#config-version=FGT60D-6.02-FW-build1066-200327:opmode=0:vdom=0\n")
    assert "FW_KNOWN_EXPLOITED" not in rule_ids(old_style)
    assert "patch level" in rules_for(old_style, "FW_VERSION_REVIEW")[0].description


def test_known_exploited_needs_the_feature():
    res = audit(HEADER_72 + """
config system interface
    edit "wan1"
        set role wan
        set allowaccess ping
    next
end
""")
    hits = {f.affected_object.split()[0]: f for f in rules_for(res, "FW_KNOWN_EXPLOITED")}
    assert hits["CVE-2024-21762"].severity is Severity.LOW
    assert "isn't enabled" in hits["CVE-2024-21762"].description


def test_any_remote_log_destination_counts():
    res = audit("""
config log syslogd2 setting
    set status enable
    set server "10.0.0.9"
end
config log disk setting
    set status enable
end
""")
    ids = rule_ids(res)
    assert "LOG_NO_FORTIANALYZER" not in ids
    assert "LOG_SHORT_RETENTION" not in ids
    assert "LOG_TRANSPORT_INSECURE" in ids


def test_default_disk_retention_is_applied():
    res = audit("config log disk setting\n    set status enable\nend\n")
    hits = rules_for(res, "LOG_SHORT_RETENTION")
    assert len(hits) == 1 and "7 days" in hits[0].description


def test_ssl_profile_that_hides_bad_certificates():
    res = audit("""
config firewall ssl-ssh-profile
    edit "custom-deep"
        set caname "Corp_Inspection_CA"
        config https
            set status deep-inspection
            set untrusted-server-cert ignore
        end
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set utm-status enable
        set av-profile "default"
        set ssl-ssh-profile "custom-deep"
    next
end
""")
    ids = rule_ids(res)
    assert "PROFILE_SSL_CERT_CHECKS_IGNORED" in ids
    assert "PROFILE_SSL_DEFAULT_CA" not in ids


def test_web_filter_without_threat_categories():
    res = audit("""
config webfilter profile
    edit "light"
        config ftgd-wf
            config filters
                edit 1
                    set category 26
                    set action block
                next
            end
        end
    next
end
config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set utm-status enable
        set webfilter-profile "light"
    next
end
""")
    hits = rules_for(res, "PROFILE_THREAT_CATEGORIES_ALLOWED")
    assert len(hits) == 1
    assert "Phishing (61)" in hits[0].description and "(26)" not in hits[0].description


def test_ldap_and_vpn_users_without_mfa():
    res = audit("""
config user ldap
    edit "AD"
        set server "10.0.0.5"
        set username "CN=svc-fw,OU=Service,DC=corp,DC=local"
    next
end
config user local
    edit "alice"
        set passwd ENC abc
    next
    edit "bob"
        set two-factor fortitoken
        set passwd ENC abc
    next
    edit "carol"
        set passwd ENC abc
    next
end
config user group
    edit "VPN"
        set member "alice" "bob"
    next
end
config vpn ssl settings
    set source-interface "wan1"
    config authentication-rule
        edit 1
            set groups "VPN"
            set portal "full-access"
        next
    end
end
""")
    assert "AUTH_LDAP_CLEARTEXT" in rule_ids(res)
    users = rules_for(res, "AUTH_USER_NO_MFA")
    assert len(users) == 1 and users[0].affected_object == "alice"


def test_unused_objects_are_aggregated_and_skip_factory_ones():
    res = audit("""
config firewall address
    edit "all"
    next
    edit "FIREWALL_AUTH_PORTAL_ADDRESS"
    next
    edit "VPN_POOL"
        set type iprange
        set start-ip 10.212.134.200
        set end-ip 10.212.134.210
    next
    edit "OLD_1"
        set subnet 10.99.0.1 255.255.255.255
    next
    edit "OLD_2"
        set subnet 10.99.0.2 255.255.255.255
    next
end
config firewall service custom
    edit "HTTPS"
        set tcp-portrange 443
    next
end
config vpn ssl settings
    set tunnel-ip-pools "VPN_POOL"
end
""")
    hits = rules_for(res, "OBJ_UNUSED_ADDRESS")
    assert len(hits) == 1
    assert "OLD_1, OLD_2" in hits[0].description and "VPN_POOL" not in hits[0].description
    assert "OBJ_UNUSED_SERVICE" not in rule_ids(res)


def test_modern_zone_default_is_not_reported():
    zone = """
config system zone
    edit "Z"
        set interface "a" "b"
    next
end
"""
    assert "ZONE_INTRAZONE_IMPLICIT" not in rule_ids(audit(HEADER_72 + zone))
    old = audit("#config-version=FGT60-5.0.7-FW-build0100-140101:opmode=0:vdom=0\n" + zone)
    assert "ZONE_INTRAZONE_IMPLICIT" in rule_ids(old)


def test_standard_backup_is_detected(broken_result):
    assert broken_result.meta["dump_style"] == "standard"
    assert any("factory default" in w for w in broken_result.meta["coverage"]["warnings"])


def test_score_is_capped_by_serious_findings():
    from fgaudit.findings import Category, Confidence, Finding
    from fgaudit.scoring import overall_score

    def finding(severity, confidence=Confidence.HIGH):
        return Finding("X", "root", Category.HARDENING, severity, confidence, "o", "t", "d",
                       "i", "r")

    assert overall_score([finding(Severity.CRITICAL)]) == 49
    assert overall_score([finding(Severity.HIGH)]) == 79
    assert overall_score([finding(Severity.CRITICAL, Confidence.LOW)]) == 95
    assert overall_score([]) == 100
