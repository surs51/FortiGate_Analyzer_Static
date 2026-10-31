from fgaudit.object_resolver.algebra import (
    BUILTIN_SERVICES,
    V4,
    V6,
    IntervalSet,
    InterfaceSet,
    IPSet,
    ServiceSet,
    ipset_from_range,
    ipset_from_subnet_tokens,
    ipset_to_strings,
    parse_port_intervals,
    service_to_strings,
)


def test_merge_overlapping_and_adjacent():
    s = IntervalSet.of([(1, 5), (4, 9), (10, 12), (20, 25)])
    assert s.intervals == ((1, 12), (20, 25))


def test_subset_and_difference():
    big = IntervalSet.of([(0, 100)])
    small = IntervalSet.of([(5, 10), (50, 60)])
    assert small.is_subset_of(big)
    assert not big.is_subset_of(small)
    assert big.difference(small).intervals == ((0, 4), (11, 49), (61, 100))


def test_intersection_and_complement():
    a = IntervalSet.of([(0, 10), (20, 30)])
    b = IntervalSet.of([(5, 25)])
    assert a.intersection(b).intervals == ((5, 10), (20, 25))
    assert not a.intersection(IntervalSet.of([(40, 50)]))
    assert a.complement(0, 40).intervals == ((11, 19), (31, 40))


def test_covers_point():
    s = IntervalSet.of([(10, 20)])
    assert s.covers(10) and s.covers(20) and not s.covers(21)


def test_subnet_tokens_and_range():
    s = ipset_from_subnet_tokens(["10.0.0.0", "255.255.255.0"])
    assert s.v4.count() == 256
    r = ipset_from_range("10.0.0.5", "10.0.0.9")
    assert r.is_subset_of(s)
    assert not s.is_subset_of(r)


def test_dual_stack_universe_covers_any_opaque():
    assert IPSet.universe().covers(IPSet.opaque_of("fqdn:example.com"))
    assert not ipset_from_subnet_tokens(["10.0.0.0/8"]).covers(IPSet.opaque_of("fqdn:example.com"))


def test_family_universe_covers_only_its_family():
    v4_fqdn = IPSet.opaque_of("fqdn:example.com", V4)
    v6_fqdn = IPSet.opaque_of("fqdn:example.com", V6)
    assert IPSet.v4_universe().covers(v4_fqdn)
    assert not IPSet.v4_universe().covers(v6_fqdn)
    assert IPSet.v6_universe().covers(v6_fqdn)


def test_opaque_only_covers_same_tag():
    a = IPSet.opaque_of("fqdn:example.com")
    assert a.covers(IPSet.opaque_of("fqdn:example.com"))
    assert not a.covers(IPSet.opaque_of("fqdn:other.com"))


def test_bad_input_is_opaque_not_empty():
    s = ipset_from_subnet_tokens(["not-an-ip"])
    assert s.has_opaque() and not s.is_empty()


def test_complement_of_determinate_set_is_exact():
    bad = ipset_from_subnet_tokens(["10.66.0.0/16"])
    rest = bad.complement({V4})
    assert not rest.inexact
    assert rest.is_broad()
    assert not rest.v4.covers(int_ip("10.66.1.1"))
    assert rest.covers(ipset_from_subnet_tokens(["8.8.8.8"]))


def test_complement_of_opaque_set_never_claims_coverage():
    geo = IPSet.opaque_of("geography:RU", V4)
    rest = geo.complement({V4})
    assert rest.inexact and rest.is_v4_universe()
    assert not rest.covers(ipset_from_subnet_tokens(["8.8.8.8"]))


def test_minus_with_unresolvable_part_is_inexact():
    left = IPSet.v4_universe().minus(IPSet.opaque_of("fqdn:x", V4))
    assert left.inexact
    assert not left.covers(ipset_from_subnet_tokens(["1.1.1.1"]))


def test_ipset_to_strings():
    assert ipset_to_strings(IPSet.universe()) == ["any address"]
    assert ipset_to_strings(IPSet.v4_universe()) == ["any IPv4 address"]
    s = ipset_from_subnet_tokens(["192.168.1.0", "255.255.255.0"])
    assert ipset_to_strings(s) == ["192.168.1.0/24"]
    assert ipset_to_strings(IPSet.opaque_of("fqdn:a.example", V4)) == ["fqdn:a.example"]


def test_service_all_covers_everything():
    all_svc = ServiceSet.all()
    https = BUILTIN_SERVICES["HTTPS"]
    assert all_svc.covers(https)
    assert not https.covers(all_svc)
    assert all_svc.is_all()
    assert all_svc.covers(ServiceSet.opaque_of("isdb"))


def test_service_protocol_isolation():
    tcp443 = BUILTIN_SERVICES["HTTPS"]
    udp443 = ServiceSet(udp=IntervalSet.closed(443, 443))
    assert not tcp443.covers(udp443)
    assert not tcp443.overlaps(udp443)


def test_service_intersection_and_complement():
    web = ServiceSet(tcp=IntervalSet.of([(80, 80), (443, 443)]))
    assert ServiceSet.all().intersection(web) == web
    assert web.intersection(BUILTIN_SERVICES["HTTPS"]).tcp.intervals == ((443, 443),)
    everything_else = BUILTIN_SERVICES["HTTPS"].complement()
    assert not everything_else.tcp.covers(443) and everything_else.tcp.covers(22)
    assert everything_else.udp.covers(443)


def test_whole_protocol_detection():
    assert BUILTIN_SERVICES["ALL_TCP"].whole_protocols() == ["TCP"]
    assert ServiceSet(tcp=IntervalSet.closed(1, 65535)).whole_protocols() == ["TCP"]
    assert BUILTIN_SERVICES["HTTPS"].whole_protocols() == []


def test_parse_port_intervals_dst_side_only():
    iv = parse_port_intervals(["443:1024-65535", "8000-8100", "22,80", "90-85"])
    assert iv.covers(443) and iv.covers(8050) and iv.covers(22) and iv.covers(80)
    assert iv.covers(87)
    assert not iv.covers(1024)


def test_service_to_strings():
    assert service_to_strings(ServiceSet.all()) == ["ALL"]
    assert service_to_strings(BUILTIN_SERVICES["DNS"]) == ["tcp/53", "udp/53"]


def test_interface_any_superset():
    any_set = InterfaceSet.any()
    named = InterfaceSet.of(["wan1", "dmz"])
    assert any_set.is_superset_of(named)
    assert not named.is_superset_of(any_set)
    assert named.is_superset_of(InterfaceSet.of(["dmz"]))
    assert named.intersects(InterfaceSet.of(["dmz", "lan"]))
    assert not named.intersects(InterfaceSet.of(["lan"]))


def int_ip(s: str) -> int:
    import ipaddress
    return int(ipaddress.ip_address(s))
