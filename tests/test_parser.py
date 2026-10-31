from fgaudit.parser import parse_config, split_line

BASIC = """
config system global
    set hostname "my fw"
    set admintimeout 5
end
config firewall address
    edit "HOST_A"
        set subnet 10.0.0.1 255.255.255.255
    next
    edit "quoted name"
        set comment "hello \\"world\\""
    next
end
"""


def test_scalar_and_table_sections():
    m = parse_config(BASIC)
    g = m.singleton("system global")
    assert g is not None and g.get("hostname") == "my fw"
    addrs = m.objects("firewall address", "root")
    assert {a.name for a in addrs} == {"HOST_A", "quoted name"}
    assert addrs[0].line > 0


def test_nested_config_inside_edit():
    m = parse_config("""
config firewall ssl-ssh-profile
    edit "deep"
        set caname "MyCA"
        config https
            set status deep-inspection
        end
        config ssh
            set status disable
        end
    next
end
""")
    prof = m.objects("firewall ssl-ssh-profile", "root")[0]
    assert prof.get("caname") == "MyCA"
    assert prof.child_singleton("https").get("status") == "deep-inspection"
    assert prof.child_singleton("ssh").get("status") == "disable"


def test_nested_tables_inside_singleton_stay_attached():
    m = parse_config("""
config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
        edit "UNDERLAY"
        next
    end
    config members
        edit 1
            set interface "port1"
            set zone "UNDERLAY"
        next
    end
    config service
        edit 1
            set dst "SAAS"
        next
    end
end
""")
    assert m.sections_present() == {"system sdwan"}
    sdwan = m.singleton("system sdwan")
    assert [z.name for z in sdwan.child("zone")] == ["virtual-wan-link", "UNDERLAY"]
    assert sdwan.child("members")[0].get("interface") == "port1"
    assert sdwan.child("service")[0].get("dst") == "SAAS"


def test_three_levels_of_nesting():
    m = parse_config("""
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        config ipv6
            set ip6-address 2001:db8::1/64
            config ip6-extra-addr
                edit 2001:db8::2/64
                next
            end
        end
    next
end
""")
    assert m.sections_present() == {"system interface"}
    port1 = m.objects("system interface", "root")[0]
    ipv6 = port1.child_singleton("ipv6")
    assert ipv6.get("ip6-address") == "2001:db8::1/64"
    assert ipv6.child("ip6-extra-addr")[0].name == "2001:db8::2/64"


MULTI_VDOM = """
config vdom
edit VD1
config firewall policy
    edit 1
        set srcintf "port1"
        set action accept
    next
end
end
config vdom
edit VD2
config firewall policy
    edit 7
        set srcintf "port2"
    next
end
end
config global
config system global
    set hostname "gw"
end
end
"""


def test_multi_vdom_scoping():
    m = parse_config(MULTI_VDOM)
    assert m.multi_vdom
    assert set(m.vdoms) >= {"VD1", "VD2", "global"}
    assert [p.name for p in m.local_objects("firewall policy", "VD1")] == ["1"]
    assert [p.name for p in m.local_objects("firewall policy", "VD2")] == ["7"]
    assert m.singleton("system global", "global").get("hostname") == "gw"


def test_multiline_quoted_value_does_not_desync():
    text = (
        'config system replacemsg-group\n'
        '    edit "g1"\n'
        '        set buffer "line one\nconfig fake\nend\nline two"\n'
        '    next\n'
        'end\n'
        'config firewall address\n'
        '    edit "AFTER"\n'
        '        set subnet 10.1.1.1 255.255.255.255\n'
        '    next\n'
        'end\n'
    )
    m = parse_config(text)
    assert [a.name for a in m.objects("firewall address", "root")] == ["AFTER"]


def test_truncated_input_flushes():
    m = parse_config('config firewall address\n    edit "X"\n        set subnet 1.2.3.4 255.255.255.255\n')
    assert [a.name for a in m.objects("firewall address", "root")] == ["X"]


def test_byte_order_mark_is_ignored():
    m = parse_config('﻿config firewall address\n    edit "X"\n    next\nend\n')
    assert [a.name for a in m.objects("firewall address", "root")] == ["X"]


def test_tokenizer_keeps_hash_and_apostrophe():
    assert split_line('set comments "ticket #42"') == ["set", "comments", "ticket #42"]
    assert split_line("set comments O'Brien's") == ["set", "comments", "O'Brien's"]
    assert split_line('set member "a b" "c"') == ["set", "member", "a b", "c"]


def test_unknown_stanza_tolerated(broken_text):
    m = parse_config(broken_text)
    assert m.objects("some-unknown-future-stanza", "root")
