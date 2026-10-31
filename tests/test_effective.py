import ipaddress

from fgaudit.object_resolver import SetResolver
from fgaudit.object_resolver.algebra import tag_label, ipset_from_subnet_tokens
from fgaudit.parser import parse_config

CFG = """
config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.0
        set role wan
    next
    edit "lan1"
        set ip 192.168.1.1 255.255.255.0
    next
end
config system zone
    edit "INSIDE"
        set interface "lan1" "lan2"
    next
end
config firewall address
    edit "NET_A"
        set subnet 10.1.0.0 255.255.0.0
    next
    edit "HOST_1"
        set subnet 10.1.2.3 255.255.255.255
    next
    edit "RANGE_1"
        set type iprange
        set start-ip 10.9.0.1
        set end-ip 10.9.0.10
    next
    edit "CLOUD"
        set type fqdn
        set fqdn "svc.example.com"
    next
    edit "NO_SUBNET_SET"
        set comment "left at the default of 0.0.0.0/0"
    next
end
config firewall addrgrp
    edit "GRP_OUTER"
        set member "GRP_INNER" "RANGE_1"
    next
    edit "GRP_INNER"
        set member "NET_A" "CLOUD"
    next
    edit "LOOP_A"
        set member "LOOP_B"
    next
    edit "LOOP_B"
        set member "LOOP_A"
    next
    edit "NET_A_BUT_HOST"
        set member "NET_A"
        set exclude enable
        set exclude-member "HOST_1"
    next
end
config firewall vip
    edit "WEB_VIP"
        set extip 203.0.113.50
        set mappedip 10.1.2.3
        set portforward enable
        set extport 8443
        set mappedport 443
    next
    edit "LB"
        set type server-load-balance
        set extip 203.0.113.60
        set extport 443
        config realservers
            edit 1
                set ip 10.1.5.1
                set port 8443
            next
        end
    next
end
config firewall service custom
    edit "WEB_PORTS"
        set tcp-portrange 80 443 8000-8010
    next
    edit "MYPROTO"
        set protocol IP
        set protocol-number 47
    next
    edit "ANY_IP"
        set protocol IP
    next
end
config firewall service group
    edit "WEB_GROUP"
        set member "WEB_PORTS" "DNS"
    next
end
config firewall profile-group
    edit "strict"
        set av-profile "default"
        set ips-sensor "default"
        set ssl-ssh-profile "deep-inspection"
    next
end
config firewall policy
    edit 1
        set srcintf "INSIDE"
        set dstintf "wan1"
        set srcaddr "GRP_OUTER"
        set dstaddr "all"
        set service "WEB_GROUP"
        set action accept
    next
    edit 2
        set srcintf "wan1"
        set dstintf "lan1"
        set srcaddr "NET_A"
        set srcaddr-negate enable
        set dstaddr "WEB_VIP"
        set service "ALL"
        set action accept
        set utm-status enable
        set profile-type group
        set profile-group "strict"
    next
    edit 3
        set srcintf "lan1"
        set dstintf "wan1"
        set srcaddr "all"
        set internet-service enable
        set internet-service-name "Microsoft-Office365"
        set action deny
    next
end
"""


def make_resolver():
    return SetResolver(parse_config(CFG))


def int_ip(s: str) -> int:
    return int(ipaddress.ip_address(s))


def test_group_flattening_recursive():
    s = make_resolver().resolve_addr("root", "GRP_OUTER")
    assert ipset_from_subnet_tokens(["10.1.0.0/16"]).is_subset_of(s)
    assert s.v4.covers(int_ip("10.9.0.5"))
    assert "fqdn:svc.example.com" in {tag_label(t) for t in s.opaque}


def test_group_exclusion_is_subtracted():
    s = make_resolver().resolve_addr("root", "NET_A_BUT_HOST")
    assert s.v4.covers(int_ip("10.1.0.1"))
    assert not s.v4.covers(int_ip("10.1.2.3"))
    assert not s.inexact


def test_address_without_subnet_is_the_default_any():
    assert make_resolver().resolve_addr("root", "NO_SUBNET_SET").is_v4_universe()


def test_cycle_detection_is_safe():
    r = make_resolver()
    assert r.resolve_addr("root", "LOOP_A").has_opaque()
    assert r.cycles


def test_vip_resolves_to_external_ip():
    s = make_resolver().resolve_addr("root", "WEB_VIP")
    assert s.v4.covers(int_ip("203.0.113.50"))
    assert not s.v4.covers(int_ip("10.1.2.3"))


def test_vip_details_and_load_balancer_real_servers():
    r = make_resolver()
    web = r.vip_info("root", "WEB_VIP")
    assert web.portforward and web.forwarded_service().tcp.intervals == ((443, 443),)
    assert web.external_label() == "203.0.113.50:8443/tcp"
    lb = r.vip_info("root", "LB")
    assert lb.portforward
    assert lb.mapped.v4.covers(int_ip("10.1.5.1"))
    assert lb.forwarded_service().tcp.covers(8443)


def test_unknown_name_is_opaque_not_empty():
    r = make_resolver()
    s = r.resolve_addr("root", "DOES_NOT_EXIST")
    assert s.has_opaque() and not s.is_empty()
    assert "DOES_NOT_EXIST" in r.unresolved


def test_service_group_builtin_and_ip_protocols():
    r = make_resolver()
    s = r.resolve_service("root", "WEB_GROUP")
    assert s.tcp.covers(443) and s.tcp.covers(8005) and s.udp.covers(53)
    assert not s.tcp.covers(22)
    assert r.resolve_service("root", "MYPROTO").ip_proto.covers(47)
    assert r.resolve_service("root", "ANY_IP").is_all()


def test_empty_service_list_means_all():
    assert make_resolver().resolve_service_list("root", []).is_all()


def test_zone_expansion_and_effective_policy():
    eff = make_resolver().effective_policies("root")
    ep = eff[0]
    assert ep.src_intf.names == {"lan1", "lan2"}
    assert ep.dst_intf.names == {"wan1"}
    assert ep.dst_ip.is_v4_universe()
    assert not ep.dst_ip.v6
    assert ep.action == "accept" and ep.enabled


def test_negated_source_becomes_everything_else():
    ep = make_resolver().effective_policies("root")[1]
    assert ep.src_negated
    assert ep.src_ip.is_broad()
    assert not ep.src_ip.v4.covers(int_ip("10.1.0.5"))
    assert any("everything except" in d for d in ep.src_display)


def test_profile_group_and_vip_narrowing():
    ep = make_resolver().effective_policies("root")[1]
    assert ep.profiles == {"av-profile": "default", "ips-sensor": "default"}
    assert ep.ssl_profile == "deep-inspection"
    assert ep.targets_vip and ep.service.is_all()
    assert ep.inbound_service().tcp.intervals == ((443, 443),)


def test_internet_service_destination_is_not_empty():
    ep = make_resolver().effective_policies("root")[2]
    assert ep.uses_isdb and not ep.matches_nothing()
    assert not ep.dst_ip.is_empty()


def test_sdwan_zone_expands_to_member_links():
    r = SetResolver(parse_config("""
config system sdwan
    set status enable
    config zone
        edit "ISP"
        next
    end
    config members
        edit 1
            set interface "port1"
            set zone "ISP"
        next
        edit 2
            set interface "port2"
            set zone "ISP"
        next
        edit 3
            set interface "port3"
        next
    end
end
"""))
    assert set(r.zone_members("root", "ISP")) == {"port1", "port2"}
    assert r.zone_members("root", "virtual-wan-link") == ["port3"]
    assert r.resolve_intf("root", ["ISP"]).names == {"port1", "port2"}


def test_multi_vdom_objects_do_not_leak_from_root():
    r = SetResolver(parse_config("""
config vdom
edit root
config firewall address
    edit "ONLY_IN_ROOT"
        set subnet 10.0.0.0 255.0.0.0
    next
end
next
edit CUST
next
end
"""))
    assert r.resolve_addr("root", "ONLY_IN_ROOT").v4
    assert r.resolve_addr("CUST", "ONLY_IN_ROOT").has_opaque()
