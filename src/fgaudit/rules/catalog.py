from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from ..findings import Category, Severity


@dataclass(frozen=True, slots=True)
class RuleMeta:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    impact: str
    recommendation: str
    references: tuple[str, ...] = ()
    compliance: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


def _r(*args, **kwargs) -> RuleMeta:
    return RuleMeta(*args, **kwargs)


_HARDENING = "https://docs.fortinet.com/document/fortigate/7.4.0/hardening-your-fortigate"
_PSIRT = "https://www.fortiguard.com/psirt"
_CIS = "CIS Fortinet FortiGate Benchmark"

S = Severity
C = Category

_RULES: tuple[RuleMeta, ...] = (
    _r("POLICY_ANY_ANY_ANY", "Rule allows any source to reach any destination on any port",
       C.FIREWALL_POLICY, S.HIGH,
       "Anything that arrives on the rule's interfaces gets through. Segmentation stops at "
       "this rule, and an attacker who lands on one side can reach everything on the other.",
       "Replace it with rules for the sources, destinations and services people actually "
       "need. If it was added as a temporary fix, remove it.",
       (_CIS,),
       {"CIS": ("4.1",), "NIST CSF": ("PR.AC-5", "PR.PT-3"), "MITRE ATT&CK": ("T1021",),
        "PCI DSS": ("1.2.1", "1.3.4"), "ISO 27001": ("A.8.20", "A.8.22")}),
    _r("POLICY_BROAD_DST_SVC", "Rule allows every service to any destination",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Every host and every port behind the destination interface is reachable, not just "
       "the few that need to be.",
       "Limit the destination to the hosts that need to be reached and the service to the "
       "ports they use.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "PCI DSS": ("1.2.1",), "ISO 27001": ("A.8.22",)}),
    _r("POLICY_BROAD_SRC_DST", "Rule uses 'all' for both source and destination",
       C.FIREWALL_POLICY, S.MEDIUM,
       "With both sides wide open, only the interfaces and the service limit the rule. "
       "There's little segmentation left between the networks involved.",
       "Use address objects for the real source and destination networks.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.22",)}),
    _r("POLICY_BROAD_SRC", "Rule accepts traffic from any source",
       C.FIREWALL_POLICY, S.LOW,
       "Any host on the source side can use this rule, including ones that were never meant to.",
       "Narrow the source to the subnets or hosts that need this access.",
       (_CIS,), {"NIST CSF": ("PR.AC-5",)}),
    _r("POLICY_SERVICE_ALL", "Rule allows all services",
       C.FIREWALL_POLICY, S.LOW,
       "Every TCP and UDP port and every other IP protocol is allowed, so the rule permits "
       "far more than the application it was written for.",
       "Set the service to the ports the application actually uses.",
       (_CIS,), {"NIST CSF": ("PR.PT-3",), "PCI DSS": ("1.2.1",)}),
    _r("POLICY_SERVICE_ALL_PROTO", "Rule allows every TCP or UDP port",
       C.FIREWALL_POLICY, S.LOW,
       "A service like ALL_TCP or ALL_UDP opens all 65,535 ports of that protocol.",
       "Replace it with service objects for the specific ports that are needed.",
       (_CIS,), {"NIST CSF": ("PR.PT-3",)}),
    _r("POLICY_NO_UTM", "Traffic is allowed without any security inspection",
       C.FIREWALL_POLICY, S.MEDIUM,
       "No IPS, antivirus, web, DNS or application control looks at this traffic, so malware "
       "and exploit attempts pass straight through.",
       "Attach security profiles to the rule, at least IPS and antivirus, and make sure "
       "utm-status is enabled.",
       (_CIS, _HARDENING),
       {"CIS": ("8.1",), "NIST CSF": ("DE.CM-1", "PR.PT-3"), "MITRE ATT&CK": ("T1190",),
        "PCI DSS": ("11.5",), "ISO 27001": ("A.8.7", "A.8.16")}),
    _r("POLICY_UTM_DISABLED", "Security profiles are attached but switched off",
       C.FIREWALL_POLICY, S.MEDIUM,
       "The GUI shows profiles on the rule, but with utm-status disabled none of them run. "
       "It looks protected and isn't.",
       "Set utm-status enable on the rule, or remove the profiles so the rule shows what it "
       "really does.",
       (_CIS,), {"NIST CSF": ("DE.CM-1",), "ISO 27001": ("A.8.16",)}),
    _r("POLICY_SSL_INEFFECTIVE_PAYLOAD", "Scanners can't see inside encrypted traffic",
       C.FIREWALL_POLICY, S.HIGH,
       "Antivirus, DLP, file filtering and email filtering need decrypted content. With "
       "certificate inspection or no inspection they only see the handshake, so most modern "
       "traffic goes unscanned.",
       "Use a deep-inspection SSL/SSH profile on rules where you rely on these scanners, with "
       "exemptions for sensitive categories such as banking and health.",
       (_HARDENING,),
       {"NIST CSF": ("DE.CM-1",), "MITRE ATT&CK": ("T1573",), "ISO 27001": ("A.8.24",)}),
    _r("POLICY_SSL_INEFFECTIVE_SNI", "Web or app filtering runs without SSL inspection",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Web filtering, DNS filtering and application control need at least certificate "
       "inspection to see which site an HTTPS connection goes to. Without it they miss most "
       "traffic.",
       "Use at least the certificate-inspection profile on this rule.",
       (_HARDENING,), {"NIST CSF": ("DE.CM-1",)}),
    _r("POLICY_SSL_UNKNOWN", "Couldn't tell how deep this SSL profile inspects",
       C.FIREWALL_POLICY, S.LOW,
       "The rule uses a custom SSL/SSH profile whose inspection mode isn't visible in this "
       "backup, so payload scanning may or may not work on encrypted traffic.",
       "Open the profile and confirm it uses deep inspection wherever payload scanning is "
       "expected.",
       (), {}),
    _r("POLICY_WAN_EXPOSURE", "Internet traffic can reach internal services too broadly",
       C.FIREWALL_POLICY, S.HIGH,
       "A rule from an internet-facing interface opens more than a single published service, "
       "or opens remote-access protocols that attackers scan for all day.",
       "Publish only what must be public, through VIPs. Restrict sources where you can and "
       "put IPS on the rule. Admin protocols such as RDP and SSH belong behind a VPN.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5", "DE.CM-1"), "MITRE ATT&CK": ("T1190", "T1133"),
        "PCI DSS": ("1.3.1", "1.3.2"), "ISO 27001": ("A.8.20", "A.8.22")}),
    _r("POLICY_RISKY_SERVICE", "Sensitive service allowed broadly",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Protocols such as RDP, SSH, SMB, Telnet or database ports are open to a wide range "
       "of sources. They are the usual path for password attacks and lateral movement.",
       "Allow these only from admin jump hosts or specific subnets, ideally through an "
       "inspected and authenticated path.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1021",), "ISO 27001": ("A.8.22",)}),
    _r("POLICY_LOGGING_DISABLED", "Traffic logging is turned off on an allow rule",
       C.FIREWALL_POLICY, S.LOW,
       "Sessions this rule allows leave no record, so there's nothing to look at after an "
       "incident.",
       "Set logtraffic to all, or at least utm.",
       (_CIS,),
       {"CIS": ("7.1",), "NIST CSF": ("DE.CM-1", "PR.PT-1"), "PCI DSS": ("10.2",),
        "ISO 27001": ("A.8.15",)}),
    _r("POLICY_DISABLED", "Disabled rules left in the policy table",
       C.FIREWALL_POLICY, S.INFORMATIONAL,
       "Old disabled rules slow down reviews and can be switched back on by accident.",
       "Delete disabled rules you no longer need. If you keep one on purpose, say why in its "
       "comment.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("POLICY_NO_NAME", "Rules without a name",
       C.FIREWALL_POLICY, S.LOW,
       "Unnamed rules are hard to review, talk about and match to change requests.",
       "Give every rule a short name that says what it's for.",
       (_CIS,), {"ISO 27001": ("A.5.37",)}),
    _r("POLICY_NO_COMMENT", "Rules without a comment",
       C.FIREWALL_POLICY, S.INFORMATIONAL,
       "Without a comment nobody can tell later why a rule exists or who asked for it.",
       "Add a comment with the purpose and the ticket or change number.",
       (), {"ISO 27001": ("A.5.37",)}),
    _r("POLICY_SHADOWED", "Rule never matches because an earlier rule catches its traffic",
       C.FIREWALL_POLICY, S.MEDIUM,
       "An earlier rule with the same action and the same inspection already matches "
       "everything this rule would. This one is dead weight, and it may hide a restriction "
       "someone thinks is in place.",
       "Remove it, or move it above the broader rule if it's meant to be more specific.",
       (_CIS,), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.9",)}),
    _r("POLICY_DUPLICATE", "Duplicate rule",
       C.FIREWALL_POLICY, S.LOW,
       "Two rules match exactly the same traffic and treat it the same way. The second one "
       "never does anything.",
       "Delete the later copy.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("POLICY_NEAR_DUPLICATE", "Two rules match the same traffic but treat it differently",
       C.FIREWALL_POLICY, S.INFORMATIONAL,
       "Only the first one ever applies. If the difference (schedule, NAT, inspection or "
       "logging) matters, the second rule's version is silently ignored.",
       "Decide which behaviour you want and keep one rule.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("POLICY_EXPIRED_SCHEDULE", "Rule uses a one-time schedule that has already ended",
       C.FIREWALL_POLICY, S.LOW,
       "The rule can't match anymore. It's leftover configuration that makes the policy look "
       "more open than it is.",
       "Remove the rule, or give it a new schedule if the access is still needed.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("POLICY_EXCESSIVE_COUNT", "Very large policy table",
       C.FIREWALL_POLICY, S.INFORMATIONAL,
       "Big rule sets are hard to review and tend to collect stale, overlapping and overly "
       "broad rules.",
       "Plan a clean-up: remove unused rules and merge similar ones with address and service "
       "groups.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("POLICY_SHADOW_CONFLICT", "Rule never takes effect because an earlier rule does the opposite",
       C.FIREWALL_POLICY, S.CRITICAL,
       "FortiGate stops at the first matching rule. An earlier rule with the opposite action "
       "catches all of this rule's traffic, so a block here doesn't block anything, or an "
       "allow here never allows anything.",
       "Move this rule above the broader one, or narrow the broader rule so it no longer "
       "covers this traffic.",
       (_CIS,),
       {"CIS": ("4.1",), "NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1562",),
        "PCI DSS": ("1.2.1",), "ISO 27001": ("A.8.20", "A.8.9")}),
    _r("POLICY_SHADOW_PROFILES", "Rule's security profiles never run",
       C.FIREWALL_POLICY, S.HIGH,
       "An earlier allow rule with different profiles catches all of this rule's traffic, so "
       "the inspection configured here is never applied.",
       "Move this rule above the broader one, give both rules the same profiles, or remove "
       "the one that can't be reached.",
       (_CIS,),
       {"NIST CSF": ("DE.CM-1", "PR.AC-5"), "ISO 27001": ("A.8.16", "A.8.9")}),
    _r("POLICY_DENY_PARTIAL_OVERLAP", "Part of a block rule is bypassed by an earlier allow",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Some of the traffic this rule is meant to block is allowed by an earlier rule first. "
       "The block only works for the part the earlier rule doesn't cover.",
       "Move the block rule above the allow rule, or cut the overlapping range out of the "
       "allow rule.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "PCI DSS": ("1.2.1",), "ISO 27001": ("A.8.20",)}),
    _r("POLICY_DENY_SKIPS_VIP", "Block rule doesn't apply to published servers",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Traffic to a VIP is translated before the rule lookup, and deny rules only see that "
       "traffic when match-vip is enabled. Without it, sources this rule is meant to block "
       "(a country block list, for example) can still reach the published server.",
       "Enable match-vip on the deny rule (set match-vip enable), or add the restriction to "
       "the rules that reference the VIP.",
       (_HARDENING,),
       {"NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1190",), "ISO 27001": ("A.8.20",)}),
    _r("POLICY_INTERFACE_ANY", "Rule uses 'any' as an interface",
       C.FIREWALL_POLICY, S.MEDIUM,
       "The rule applies between every pair of interfaces, including paths nobody had in "
       "mind when writing it.",
       "Set explicit source and destination interfaces or zones.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.22",)}),
    _r("POLICY_ZERO_HIT", "Enabled rules that never matched any traffic",
       C.FIREWALL_POLICY, S.MEDIUM,
       "Going by the hit counters you provided, nobody uses these rules. Unused access is "
       "still open access.",
       "Make sure the counters cover a long enough period, such as a full business cycle, "
       "then disable these rules and remove them later.",
       (), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.9",)}),
    _r("EXPOSURE_NAKED_SERVICE", "Service reachable from the internet without any inspection",
       C.FIREWALL_POLICY, S.HIGH,
       "A server is reachable from the internet and the rule that lets traffic in has no "
       "security profile. Exploit attempts reach it untouched, and published servers are "
       "among the first things attackers probe.",
       "Add IPS to the rule (and antivirus where files are exchanged), use deep inspection if "
       "the service uses TLS and you can load its certificate, and limit sources where you can.",
       (_CIS, _HARDENING),
       {"CIS": ("8.1",), "NIST CSF": ("DE.CM-1", "PR.AC-5"), "MITRE ATT&CK": ("T1190",),
        "PCI DSS": ("1.3.1", "11.5"), "ISO 27001": ("A.8.7", "A.8.20")}),

    _r("OBJ_UNUSED_ADDRESS", "Unused address objects",
       C.OBJECTS, S.INFORMATIONAL,
       "Objects that nothing references clutter the configuration and are easy to reuse by "
       "mistake.",
       "Delete them after checking that nothing outside this firewall (FortiManager, scripts) "
       "depends on them.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("OBJ_UNUSED_SERVICE", "Unused custom services",
       C.OBJECTS, S.INFORMATIONAL,
       "Custom services that nothing references are clutter.",
       "Delete custom services you no longer need.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("OBJ_NESTED_GROUP_DEPTH", "Groups nested too deeply",
       C.OBJECTS, S.LOW,
       "Deep nesting hides what a rule really allows and makes mistakes easy to miss in review.",
       "Flatten the hierarchy so groups are at most a few levels deep.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("OBJ_DUPLICATE_ADDRESS", "Several address objects for the same network",
       C.OBJECTS, S.LOW,
       "When one network has several names, rules drift apart as people update one object "
       "and not the others.",
       "Keep one object per network and point all rules at it.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("OBJ_OVERLAPPING_SUBNET", "Address objects that overlap",
       C.OBJECTS, S.INFORMATIONAL,
       "One network sits inside another under a different name. That's often fine, but it can "
       "hide conflicting intent.",
       "Check the pair and remove whichever one is left over, if any.",
       (), {}),
    _r("OBJ_ORPHAN_VIP", "VIP that no rule uses",
       C.OBJECTS, S.LOW,
       "A VIP without a rule does nothing today, but it's a half-finished publication. If a "
       "broad rule is added later, the server behind it becomes reachable without anyone "
       "noticing.",
       "Delete it if the service is gone, or tie it to a specific, inspected rule.",
       (), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.9",)}),
    _r("OBJ_ORPHAN_IPPOOL", "IP pools that nothing uses",
       C.OBJECTS, S.INFORMATIONAL,
       "Unused NAT pools are leftover configuration.",
       "Delete unused IP pools.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("OBJ_EMPTY_GROUP", "Empty address or service group",
       C.OBJECTS, S.LOW,
       "A group without members usually matches nothing, which quietly disables any rule "
       "that uses it. That's almost always a mistake.",
       "Add the intended members, or remove the group and the rules that use it.",
       (), {"ISO 27001": ("A.8.9",)}),

    _r("ADMIN_LOCAL_ACCOUNT", "Local administrator accounts",
       C.ADMIN, S.INFORMATIONAL,
       "Local accounts live only on this firewall. Your central password, MFA and offboarding "
       "processes don't reach them, so old accounts tend to linger.",
       "Authenticate admins against RADIUS, TACACS+ or LDAP with MFA. Keep a single local "
       "break-glass account with a long password stored offline.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-1",), "PCI DSS": ("8.2",), "ISO 27001": ("A.5.16",)}),
    _r("ADMIN_NO_MFA", "Admin accounts without two-factor authentication",
       C.ADMIN, S.HIGH,
       "A stolen or guessed password is enough to take over the firewall.",
       "Enable two-factor authentication (FortiToken, email or SMS) for every admin, or "
       "enforce MFA on the RADIUS or LDAP server that authenticates them.",
       (_CIS,),
       {"CIS": ("3.1",), "NIST CSF": ("PR.AC-7",), "MITRE ATT&CK": ("T1078",),
        "PCI DSS": ("8.4", "8.5"), "ISO 27001": ("A.8.5",)}),
    _r("ADMIN_MULTIPLE_SUPER_ADMIN", "Several accounts with full super_admin rights",
       C.ADMIN, S.MEDIUM,
       "Each super_admin account can change anything. The more of them there are, the more "
       "ways in, and the harder it is to tell who changed what.",
       "Keep super_admin to one or two accounts and give everyone else a profile limited to "
       "their job.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-4",), "PCI DSS": ("7.2",), "ISO 27001": ("A.8.2",)}),
    _r("ADMIN_WEAK_PASSWORD_POLICY", "Weak password rules for admins",
       C.ADMIN, S.MEDIUM,
       "Without length and complexity rules, admins can set short passwords that are quick "
       "to guess.",
       "Enable the admin password policy with a minimum length of 12 and at least two "
       "character types (config system password-policy).",
       (_CIS,),
       {"CIS": ("2.1",), "NIST CSF": ("PR.AC-1",), "PCI DSS": ("8.3",),
        "ISO 27001": ("A.5.17",)}),
    _r("ADMIN_NO_TRUSTED_HOST", "Admin accounts that can log in from anywhere",
       C.ADMIN, S.HIGH,
       "Without trusted hosts, anyone who can reach the admin interface can try these "
       "accounts' passwords.",
       "Set trusthost entries to your management networks. Trusted hosts only help if every "
       "admin account has them, and they don't stop attacks that happen before login, so "
       "also restrict the admin interfaces with a local-in policy.",
       (_CIS,),
       {"CIS": ("3.2",), "NIST CSF": ("PR.AC-5",), "PCI DSS": ("1.3.1",),
        "ISO 27001": ("A.8.20",)}),
    _r("ADMIN_API_EXCESSIVE_PRIV", "API user with too much access",
       C.ADMIN, S.MEDIUM,
       "API tokens don't expire on their own and often end up in scripts. A token with "
       "super_admin rights or no source restriction is very valuable to steal.",
       "Give the API user a profile limited to what the automation needs and restrict it to "
       "the hosts that call the API.",
       (), {"NIST CSF": ("PR.AC-4",), "ISO 27001": ("A.8.2",)}),
    _r("ADMIN_INSECURE_ACCESS", "Unencrypted admin access (HTTP or Telnet)",
       C.ADMIN, S.HIGH,
       "Telnet sends passwords in clear text. HTTP only redirects to HTTPS, but someone on "
       "the path can intercept that redirect.",
       "Remove telnet and http from allowaccess on every interface and use SSH and HTTPS only.",
       (_CIS,),
       {"CIS": ("1.1",), "NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1040",),
        "PCI DSS": ("2.2.5", "4.2"), "ISO 27001": ("A.8.24",)}),
    _r("ADMIN_DEFAULT_NAME", "Default 'admin' account still exists",
       C.ADMIN, S.LOW,
       "'admin' is the first username every attacker tries, so keeping it gives away half of "
       "the login.",
       "Create personal admin accounts, then rename or delete the default 'admin' account.",
       (_CIS,), {"NIST CSF": ("PR.AC-1",), "ISO 27001": ("A.5.16",)}),
    _r("ADMIN_WILDCARD_REMOTE", "Any member of a remote group becomes an admin",
       C.ADMIN, S.MEDIUM,
       "With wildcard enabled, every user in the remote RADIUS or LDAP group gets this admin "
       "profile. Group membership on another system decides who controls the firewall.",
       "Keep that group tightly controlled, or create individual admin accounts. Avoid "
       "combining wildcard with super_admin.",
       (), {"NIST CSF": ("PR.AC-4",), "ISO 27001": ("A.8.2",)}),

    _r("AUTH_LDAP_CLEARTEXT", "LDAP server used without encryption",
       C.AUTH, S.MEDIUM,
       "The firewall sends usernames and passwords to the directory in clear text, including "
       "the bind account's. Anyone who can capture traffic between the two can read them.",
       "Set secure to ldaps or starttls on the LDAP server entry and verify the server "
       "certificate.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1040",), "PCI DSS": ("4.2",),
        "ISO 27001": ("A.8.24",)}),
    _r("AUTH_USER_NO_MFA", "VPN users without two-factor authentication",
       C.AUTH, S.MEDIUM,
       "Remote access is protected by a password alone. Password spraying against VPN "
       "portals is one of the most common ways into a network.",
       "Enable two-factor authentication for these users, or authenticate them through an "
       "identity provider that enforces MFA (SAML, or RADIUS with MFA).",
       (_CIS,),
       {"NIST CSF": ("PR.AC-7",), "MITRE ATT&CK": ("T1078", "T1133"), "PCI DSS": ("8.4",),
        "ISO 27001": ("A.8.5",)}),

    _r("IFACE_MGMT_ON_WAN", "Firewall management is reachable from the internet",
       C.INTERFACE, S.CRITICAL,
       "The admin login page, SSH or SNMP is open on an internet-facing interface. FortiOS has "
       "had several authentication bypass bugs in the admin interface, and exposed management "
       "is scanned constantly.",
       "Remove https, http, ssh, telnet and snmp from allowaccess on internet-facing "
       "interfaces. If you have to manage over the internet, limit sources with a local-in "
       "policy or use a VPN.",
       (_CIS, _HARDENING),
       {"CIS": ("1.2",), "NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1133",),
        "PCI DSS": ("1.3.1",), "ISO 27001": ("A.8.20",)}),
    _r("IFACE_AUX_SERVICE_ON_WAN", "Fabric or FortiManager access open to the internet",
       C.INTERFACE, S.MEDIUM,
       "Security Fabric and FortiManager (fgfm) listeners on the internet side add attack "
       "surface, and the fgfm daemon has had a remotely exploitable bug.",
       "Remove fabric, fgfm and speed-test from allowaccess on internet-facing interfaces "
       "unless you need them there. If you do, restrict sources with a local-in policy.",
       (_HARDENING,),
       {"NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1133",), "ISO 27001": ("A.8.20",)}),
    _r("IFACE_UNNEEDED_PROTOCOL", "Interface allows a service that isn't set up",
       C.INTERFACE, S.LOW,
       "The interface accepts connections for a feature that isn't configured on the "
       "firewall. That's attack surface with no benefit.",
       "Remove the unused protocols from allowaccess.",
       (_CIS,), {"NIST CSF": ("PR.PT-3",), "ISO 27001": ("A.8.20",)}),
    _r("IFACE_MISSING_ROLE", "Interfaces without a role",
       C.INTERFACE, S.LOW,
       "Roles tell FortiOS, and this review, which side of the network an interface is on. "
       "Without them it's harder to tell inbound rules from outbound ones.",
       "Set role to wan, lan or dmz on each data interface.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("IFACE_INSECURE_SDWAN", "SD-WAN without health checks",
       C.INTERFACE, S.LOW,
       "Without health checks SD-WAN can't tell when a link is down or degraded, so traffic "
       "keeps going over a dead or poor path.",
       "Add at least one health check that probes every member link.",
       (), {"NIST CSF": ("PR.PT-5",)}),
    _r("IFACE_EXPOSED_LOOPBACK", "Loopback interface allows management access",
       C.INTERFACE, S.LOW,
       "A loopback address can be reached from any network that has a route and a rule to "
       "it, so its management access can end up wider than intended.",
       "Remove management protocols from the loopback, or make sure only trusted networks "
       "can reach it.",
       (), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.20",)}),
    _r("IFACE_NO_ANTISPOOF", "Anti-spoofing check turned off on an interface",
       C.INTERFACE, S.MEDIUM,
       "With src-check disabled the firewall accepts packets whose source address doesn't "
       "belong behind that interface. On an internet link that lets outsiders pose as "
       "internal hosts.",
       "Remove 'set src-check disable' unless asymmetric routing really needs it, and fix the "
       "routing if you can.",
       (), {"NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1599",), "ISO 27001": ("A.8.20",)}),

    _r("VPN_IKEV1", "IPsec tunnel uses IKEv1",
       C.VPN, S.MEDIUM,
       "IKEv1 is outdated. It lacks the protections built into IKEv2 and, with pre-shared "
       "keys, some modes allow offline key guessing.",
       "Move the tunnel to IKEv2 (set ike-version 2) and agree the change with the other side.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1573",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_WEAK_DH", "IPsec allows weak Diffie-Hellman groups",
       C.VPN, S.HIGH,
       "Groups 1, 2, 5 and 22 use small or weak parameters. A well-funded attacker can break "
       "the key exchange and decrypt recorded traffic.",
       "Use group 14 or higher, preferably 19, 20 or 21.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1573",), "PCI DSS": ("4.2",),
        "ISO 27001": ("A.8.24",)}),
    _r("VPN_WEAK_CIPHER", "IPsec allows weak encryption or hashing",
       C.VPN, S.HIGH,
       "DES and 3DES no longer protect data properly, and MD5 and SHA-1 no longer give "
       "reliable integrity.",
       "Use AES-GCM, or AES with SHA-256 or better, for example aes256gcm or aes256-sha256.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "PCI DSS": ("4.2",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_AGGRESSIVE_MODE", "IPsec tunnel uses IKEv1 aggressive mode",
       C.VPN, S.HIGH,
       "Aggressive mode sends a hash of the pre-shared key before the connection is "
       "protected. Anyone who can reach the gateway can capture it and guess the key offline.",
       "Switch the tunnel to main mode or, better, to IKEv2. Rotate the pre-shared key "
       "afterwards.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1110",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_PHASE2_WEAK", "IPsec phase 2 without forward secrecy or replay protection",
       C.VPN, S.MEDIUM,
       "Without PFS, one leaked key decrypts all past traffic of the tunnel. Without replay "
       "detection, captured packets can be sent again.",
       "Enable pfs with a strong DH group, and replay detection, on the phase 2 selector.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_SSL_WEAK_TLS", "SSL-VPN accepts old TLS versions or weak ciphers",
       C.VPN, S.HIGH,
       "TLS 1.0, TLS 1.1 and low-strength ciphers have known weaknesses and let an attacker "
       "on the path push clients to weaker encryption.",
       "Set ssl-min-proto-ver to tls1-2 and algorithm to high in vpn ssl settings.",
       (_CIS, _HARDENING),
       {"CIS": ("9.1",), "NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1133",),
        "PCI DSS": ("4.2.1",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_SSL_SPLIT_TUNNEL", "SSL-VPN split tunnelling is on",
       C.VPN, S.LOW,
       "Connected laptops reach the internet directly while also connected to your network, "
       "so their web traffic skips your inspection.",
       "Decide whether you need full tunnelling. If split tunnelling stays, make sure the "
       "endpoints have their own protection.",
       (), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.20",)}),
    _r("VPN_BROAD_ACCESS", "VPN users can reach too much",
       C.VPN, S.MEDIUM,
       "Remote users land on a rule that opens all destinations or all services. One phished "
       "VPN account then reaches almost everything.",
       "Give each VPN group access only to the servers and ports it needs.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5", "PR.AC-4"), "MITRE ATT&CK": ("T1133",),
        "ISO 27001": ("A.8.20",)}),
    _r("VPN_SSLVPN_WAN_PORTAL", "SSL-VPN portal open to the internet",
       C.VPN, S.HIGH,
       "The FortiGate SSL-VPN has had several critical bugs that let attackers in before "
       "login, and they have been exploited at scale. An internet-facing portal needs current "
       "firmware and tight controls.",
       "Keep the firmware on a fixed release, require MFA, restrict source addresses or "
       "countries, and consider moving users to IPsec VPN or ZTNA.",
       (_HARDENING,),
       {"NIST CSF": ("PR.AC-3", "ID.RA-1"), "MITRE ATT&CK": ("T1133", "T1190"),
        "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8", "A.8.20")}),
    _r("VPN_SSL_DEFAULT_CERT", "SSL-VPN uses the factory certificate",
       C.VPN, S.LOW,
       "Users see a certificate warning every time they connect and learn to click through "
       "it. That makes a fake portal much easier to pass off.",
       "Install a certificate from a trusted CA for the portal's hostname and set it as "
       "servercert.",
       (_HARDENING,), {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),
    _r("VPN_SSL_BRUTE_FORCE", "SSL-VPN doesn't lock out repeated login failures",
       C.VPN, S.MEDIUM,
       "Without a limit on failed logins, an attacker can try passwords against the portal "
       "as fast as it answers.",
       "Set login-attempt-limit (3 is common) and a login-block-time of several minutes.",
       (_HARDENING,),
       {"NIST CSF": ("PR.AC-7",), "MITRE ATT&CK": ("T1110",), "ISO 27001": ("A.8.5",)}),

    _r("PROFILE_UNUSED", "Security profile that no rule uses",
       C.SECURITY_PROFILE, S.INFORMATIONAL,
       "Unused profiles make it harder to see what inspection is really applied.",
       "Delete unused profiles or attach them where they were meant to go.",
       (), {"ISO 27001": ("A.8.9",)}),
    _r("PROFILE_IPS_MONITOR_ONLY", "IPS sensor only watches, never blocks",
       C.SECURITY_PROFILE, S.MEDIUM,
       "Every configured signature action is monitor or pass. Attacks get logged but still "
       "reach their target.",
       "Set the action to block for high and critical signatures once you've checked for "
       "false positives.",
       (), {"NIST CSF": ("DE.CM-1", "PR.PT-3"), "ISO 27001": ("A.8.16",)}),
    _r("PROFILE_AV_NO_BLOCK", "Antivirus profile only logs malware",
       C.SECURITY_PROFILE, S.MEDIUM,
       "The profile is in monitor mode, so detected malware is logged and then delivered.",
       "Set the protocols in the profile to block.",
       (), {"NIST CSF": ("DE.CM-4",), "ISO 27001": ("A.8.7",)}),
    _r("PROFILE_SSL_DEFAULT_CA", "Deep inspection uses the built-in Fortinet CA",
       C.SECURITY_PROFILE, S.MEDIUM,
       "Clients have to trust the CA that deep inspection signs with. The factory Fortinet CA "
       "isn't part of your PKI and isn't managed by you, which weakens the whole setup.",
       "Issue a subordinate CA from your own PKI for SSL inspection and push it to clients.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),
    _r("PROFILE_SSL_CERT_CHECKS_IGNORED", "Deep inspection hides invalid server certificates",
       C.SECURITY_PROFILE, S.HIGH,
       "With 'ignore', the firewall re-signs certificates it couldn't verify (untrusted, "
       "expired or revoked) with your trusted CA. Users no longer see the warning, so an "
       "attacker in the middle on the internet side goes unnoticed.",
       "Set untrusted-server-cert, expired-server-cert and revoked-server-cert to block or "
       "allow, never ignore.",
       (_HARDENING,),
       {"NIST CSF": ("PR.DS-2",), "MITRE ATT&CK": ("T1557",), "ISO 27001": ("A.8.24",)}),
    _r("PROFILE_THREAT_CATEGORIES_ALLOWED", "Filter profile doesn't block malicious or phishing sites",
       C.SECURITY_PROFILE, S.MEDIUM,
       "The FortiGuard categories for malicious websites, phishing and spam links aren't "
       "blocked in this profile, so users can still open known-bad links.",
       "Block the Malicious Websites (26), Phishing (61) and Spam URLs (86) categories.",
       (_HARDENING,),
       {"NIST CSF": ("DE.CM-1",), "MITRE ATT&CK": ("T1566",), "ISO 27001": ("A.8.23",)}),

    _r("LOG_NO_FORTIANALYZER", "Logs aren't sent off the firewall",
       C.LOGGING, S.MEDIUM,
       "Logs stay on the device, where space is limited and anyone who takes over the "
       "firewall can delete them.",
       "Send logs to FortiAnalyzer, FortiAnalyzer Cloud or a syslog/SIEM server.",
       (_CIS,),
       {"CIS": ("7.2",), "NIST CSF": ("DE.CM-1", "PR.PT-1"), "PCI DSS": ("10.5",),
        "ISO 27001": ("A.8.15",)}),
    _r("LOG_SHORT_RETENTION", "Local logs are only kept for a short time",
       C.LOGGING, S.LOW,
       "When a breach is found weeks later, the logs from the start of it are already gone.",
       "Keep logs longer (commonly 90 days searchable and a year archived), preferably on an "
       "external log server.",
       (), {"PCI DSS": ("10.5.1",), "ISO 27001": ("A.8.15",)}),
    _r("LOG_NO_EVENT", "Event logging is off",
       C.LOGGING, S.MEDIUM,
       "Admin logins, config changes, VPN and HA events aren't recorded. Those are exactly "
       "the records you need in an investigation.",
       "Turn event logging back on (config log eventfilter / set event enable).",
       (_CIS,),
       {"NIST CSF": ("DE.CM-3",), "PCI DSS": ("10.2",), "ISO 27001": ("A.8.15",)}),
    _r("LOG_TRANSPORT_INSECURE", "Syslog is sent unencrypted",
       C.LOGGING, S.LOW,
       "Log messages travel as plain UDP. They can be read on the way, forged, or dropped "
       "without anyone noticing.",
       "Use TCP syslog with TLS (set mode reliable, set enc-algorithm high), or send logs to "
       "FortiAnalyzer.",
       (), {"NIST CSF": ("PR.DS-2", "PR.PT-1"), "ISO 27001": ("A.8.15",)}),

    _r("HA_STANDALONE", "No high availability",
       C.HIGH_AVAILABILITY, S.INFORMATIONAL,
       "If this unit fails, traffic stops until it's replaced. That can be a sensible choice "
       "for a small site.",
       "If this firewall carries production traffic, consider an HA pair.",
       (), {"NIST CSF": ("PR.IP-4",), "ISO 27001": ("A.8.14",)}),
    _r("HA_NO_SESSION_SYNC", "HA doesn't sync sessions",
       C.HIGH_AVAILABILITY, S.MEDIUM,
       "On failover all open connections drop, including VPN tunnels and long transfers.",
       "Enable session-pickup in the HA settings.",
       (), {"NIST CSF": ("PR.IP-4",), "ISO 27001": ("A.8.14",)}),
    _r("HA_SPLIT_BRAIN_RISK", "HA has only one heartbeat link",
       C.HIGH_AVAILABILITY, S.MEDIUM,
       "If that one link fails, both units can become active at once, with duplicate "
       "addresses and broken traffic.",
       "Use at least two heartbeat interfaces, ideally on separate cables or switches.",
       (), {"NIST CSF": ("PR.IP-4",), "ISO 27001": ("A.8.14",)}),
    _r("HA_WEAK_AUTH", "HA heartbeat isn't protected",
       C.HIGH_AVAILABILITY, S.MEDIUM,
       "Without a group password and heartbeat protection, a device on the heartbeat network "
       "could read cluster traffic or interfere with the cluster.",
       "Set an HA password and turn on heartbeat authentication and encryption "
       "(set authentication enable, set encryption enable).",
       (_CIS,), {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),

    _r("HARDEN_WEAK_CRYPTO", "Strong cryptography is turned off",
       C.HARDENING, S.HIGH,
       "The firewall will accept weak ciphers and old protocols for its own HTTPS, SSH and "
       "FortiGuard connections.",
       "Turn it back on: config system global / set strong-crypto enable.",
       (_CIS, _HARDENING),
       {"CIS": ("1.3",), "NIST CSF": ("PR.DS-2",), "PCI DSS": ("4.2.1",),
        "ISO 27001": ("A.8.24",)}),
    _r("HARDEN_TLS_OLD", "Firewall accepts old TLS versions",
       C.HARDENING, S.MEDIUM,
       "TLS 1.0 and 1.1 have known weaknesses. The admin interface and the firewall's own "
       "connections should only use current versions.",
       "Set admin-https-ssl-versions to tlsv1-2 tlsv1-3 and ssl-min-proto-version to TLSv1-2.",
       (_CIS, _HARDENING),
       {"CIS": ("1.4",), "NIST CSF": ("PR.DS-2",), "PCI DSS": ("4.2.1",),
        "ISO 27001": ("A.8.24",)}),
    _r("HARDEN_AUTO_UPDATE_DISABLED", "Automatic FortiGuard updates are off",
       C.HARDENING, S.MEDIUM,
       "Antivirus and IPS signatures stop updating, so protection falls further behind every "
       "day.",
       "Turn scheduled updates back on under config system autoupdate schedule.",
       (_CIS,),
       {"NIST CSF": ("PR.IP-12", "ID.RA-1"), "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8",)}),
    _r("HARDEN_SECURITY_RATING_DISABLED", "Scheduled Security Rating is off",
       C.HARDENING, S.LOW,
       "The Security Rating regularly checks the firewall against Fortinet's best practices. "
       "Turning it off removes a free early warning.",
       "Enable security-rating-run-on-schedule.",
       (_CIS,), {"NIST CSF": ("ID.RA-1",), "ISO 27001": ("A.8.8",)}),
    _r("HARDEN_THREAT_FEED_MISSING", "No external threat feeds",
       C.HARDENING, S.LOW,
       "Threat feeds let rules block known-bad addresses and domains automatically. Not having "
       "one is a missed opportunity rather than a hole.",
       "If you have a feed you trust, add it under system external-resource and use it in "
       "rules or DNS filtering.",
       (), {"NIST CSF": ("ID.RA-2", "DE.CM-1")}),
    _r("HARDEN_DNS_INSECURE", "Firewall's own DNS lookups are unencrypted",
       C.HARDENING, S.LOW,
       "The firewall's own lookups (FortiGuard, FQDN objects) can be seen or tampered with on "
       "the way.",
       "Use DNS over TLS for system DNS where your resolvers support it.",
       (), {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),
    _r("HARDEN_NTP_INSECURE", "Time synchronisation is off",
       C.HARDENING, S.LOW,
       "Without correct time, logs don't line up, certificates may be misjudged and "
       "time-based tokens can fail.",
       "Enable NTP with servers you trust.",
       (_CIS,),
       {"NIST CSF": ("PR.PT-1",), "PCI DSS": ("10.4",), "ISO 27001": ("A.8.15",)}),
    _r("HARDEN_ADMIN_TIMEOUT", "Admin sessions stay open too long",
       C.HARDENING, S.LOW,
       "An unattended logged-in session can be used by whoever sits down at it or manages to "
       "hijack it.",
       "Set admintimeout to a short value, such as 5 to 10 minutes.",
       (_CIS,),
       {"CIS": ("2.2",), "NIST CSF": ("PR.AC-7",), "PCI DSS": ("8.2.8",),
        "ISO 27001": ("A.8.5",)}),
    _r("HARDEN_PRIVATE_DATA_ENCRYPTION", "Secrets in the backup use Fortinet's shared default key",
       C.HARDENING, S.MEDIUM,
       "Passwords and keys in the configuration are encrypted with a key built into FortiOS "
       "(CVE-2019-6693). Anyone who gets a copy of a backup can decrypt VPN keys, LDAP bind "
       "passwords and similar secrets.",
       "Enable private-data-encryption with your own key (config system global / set "
       "private-data-encryption enable), then change the secrets that were in older backups.",
       (_HARDENING, _PSIRT),
       {"NIST CSF": ("PR.DS-1",), "MITRE ATT&CK": ("T1552",), "ISO 27001": ("A.8.24",)}),
    _r("HARDEN_ADMIN_LOCKOUT", "Short lockout after failed admin logins",
       C.HARDENING, S.LOW,
       "After a few wrong passwords the admin login is only blocked briefly, so password "
       "guessing can carry on at a steady pace.",
       "Set admin-lockout-threshold to 3 and admin-lockout-duration to 900 seconds or more.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-7",), "MITRE ATT&CK": ("T1110",), "ISO 27001": ("A.8.5",)}),
    _r("HARDEN_SSH_WEAK_ALGO", "Admin SSH allows weak algorithms",
       C.HARDENING, S.MEDIUM,
       "Old key exchange, cipher or MAC algorithms let an attacker on the path weaken the "
       "protection of admin SSH sessions.",
       "Remove SHA-1 key exchange, CBC and other legacy ciphers, and MD5 or SHA-1 MACs from "
       "ssh-kex-algo, ssh-enc-algo and ssh-mac-algo.",
       (_HARDENING,), {"NIST CSF": ("PR.DS-2",), "ISO 27001": ("A.8.24",)}),
    _r("HARDEN_SNMP_WEAK", "SNMP is set up in a weak way",
       C.HARDENING, S.MEDIUM,
       "SNMP can reveal the whole network layout, and v1/v2c communities are plain-text "
       "passwords. A default community, or one open to any source, is an easy target.",
       "Prefer SNMPv3 with auth-priv, SHA-256 and AES. If v2c has to stay, use a random "
       "community name and list the exact monitoring hosts.",
       (_CIS, _HARDENING),
       {"NIST CSF": ("PR.AC-5", "PR.DS-2"), "MITRE ATT&CK": ("T1602",),
        "ISO 27001": ("A.8.20",)}),
    _r("HARDEN_ASYMROUTE", "Asymmetric routing is allowed",
       C.HARDENING, S.MEDIUM,
       "With asymroute enabled the firewall passes packets that don't belong to a session it "
       "has seen, so stateful checks and some security profiles no longer apply to them.",
       "Fix the routing so traffic comes back through the same firewall, then disable "
       "asymroute.",
       (_HARDENING,), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.20",)}),
    _r("HARDEN_USB_AUTO_INSTALL", "Firmware and config can be loaded from USB at boot",
       C.HARDENING, S.LOW,
       "Anyone with physical access can plug in a USB stick and load their own configuration "
       "or firmware during a reboot.",
       "Disable auto-install-config and auto-install-image under config system auto-install.",
       (_CIS,), {"NIST CSF": ("PR.AC-2",), "ISO 27001": ("A.7.2",)}),
    _r("HARDEN_LOGIN_BANNER", "No login banner",
       C.HARDENING, S.INFORMATIONAL,
       "A banner tells people that access is monitored and only for authorised users. Some "
       "regulations and internal policies require one.",
       "Enable pre-login-banner in system global and set the text under config system "
       "replacemsg admin.",
       (_CIS,), {"ISO 27001": ("A.5.10",)}),

    _r("FW_VERSION_REVIEW", "Check this firmware version against Fortinet advisories",
       C.HARDENING, S.INFORMATIONAL,
       "Which vulnerabilities apply depends on the exact firmware. An offline review can't "
       "know about advisories published after it was written.",
       "Look this model and version up on the Fortinet PSIRT site and upgrade to a fixed "
       "release if anything applies.",
       (_PSIRT,),
       {"NIST CSF": ("ID.RA-1",), "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8",)}),
    _r("FW_PSIRT_MATCH", "Firmware listed in the advisory feed you supplied",
       C.HARDENING, S.HIGH,
       "Your advisory feed names this exact model and version.",
       "Read the listed advisories and upgrade to a fixed release.",
       (_PSIRT,),
       {"NIST CSF": ("ID.RA-1",), "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8",)}),
    _r("FW_END_OF_SUPPORT", "Firmware branch is out of support",
       C.HARDENING, S.HIGH,
       "Fortinet no longer releases security fixes for this branch, so every vulnerability "
       "found from now on stays open on this firewall.",
       "Upgrade to a supported branch, following Fortinet's recommended upgrade path.",
       (_PSIRT, "https://support.fortinet.com/Information/ProductLifeCycle.aspx"),
       {"NIST CSF": ("ID.AM-2", "PR.IP-12"), "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8",)}),
    _r("FW_KNOWN_EXPLOITED", "Firmware has a vulnerability that attackers are known to use",
       C.HARDENING, S.CRITICAL,
       "This version is in the affected range of a vulnerability that has been exploited in "
       "real attacks, and the feature it lives in is in use here.",
       "Upgrade to a fixed release as soon as you can. Until then, turn off or restrict the "
       "affected feature and check the firewall for signs of compromise as the advisory "
       "describes.",
       (_PSIRT, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
       {"NIST CSF": ("ID.RA-1", "PR.IP-12"), "MITRE ATT&CK": ("T1190",),
        "PCI DSS": ("6.3.3",), "ISO 27001": ("A.8.8",)}),

    _r("ZONE_INTRAZONE_ALLOW", "Traffic between interfaces in a zone isn't filtered",
       C.INTERFACE, S.HIGH,
       "With intrazone allow, traffic between the zone's interfaces passes without any rule. "
       "If they are different segments there's no segmentation between them, and it won't "
       "show up in the policy table.",
       "Set intrazone deny and write rules for the traffic that should flow, or split "
       "unrelated networks into separate zones.",
       (_CIS,),
       {"NIST CSF": ("PR.AC-5",), "MITRE ATT&CK": ("T1021",), "PCI DSS": ("1.3.6",),
        "ISO 27001": ("A.8.22",)}),
    _r("ZONE_INTRAZONE_IMPLICIT", "Zone relies on the firmware default for intra-zone traffic",
       C.INTERFACE, S.INFORMATIONAL,
       "Very old FortiOS versions allowed traffic inside a zone by default. On those, this "
       "zone may pass traffic between its interfaces without any rule.",
       "Set intrazone explicitly, preferably to deny.",
       (), {"ISO 27001": ("A.8.9",)}),

    _r("NAT_VIP_RAW_IP", "Inbound rule points at a server's internal address instead of its VIP",
       C.FIREWALL_POLICY, S.MEDIUM,
       "In policy NAT mode, inbound rules have to reference the VIP. A rule that uses the "
       "internal address either never matches the published traffic or opens a direct path "
       "the VIP was supposed to control.",
       "Replace the internal address in dstaddr with the VIP object.",
       (), {"NIST CSF": ("PR.AC-5",), "ISO 27001": ("A.8.20",)}),
    _r("NAT_INTERNAL_SNAT", "Source NAT between internal networks",
       C.FIREWALL_POLICY, S.LOW,
       "The destination only sees the firewall's address, not the real client. That makes "
       "logs on internal servers much less useful during an investigation.",
       "Turn NAT off for internal traffic unless routing really needs it.",
       (), {"NIST CSF": ("DE.CM-1",), "ISO 27001": ("A.8.15",)}),
)

CATALOG: dict[str, RuleMeta] = {r.rule_id: r for r in _RULES}


def get_rule(rule_id: str) -> RuleMeta:
    try:
        return CATALOG[rule_id]
    except KeyError as exc:
        raise KeyError(f"Unknown rule_id: {rule_id!r}") from exc


def all_frameworks() -> list[str]:
    fw: set[str] = set()
    for rule in CATALOG.values():
        fw.update(rule.compliance.keys())
    return sorted(fw)
