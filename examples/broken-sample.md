# FortiGate configuration review

**Device:** FGVM64, FortiOS 7.2.5 (build 1517)  
**File:** `broken_config.conf` · **VDOMs:** root · **Rules:** 9 · **Reviewed:** 2026-09-23 04:20:34

## Summary

The review found 44 issues: 4 critical, 12 high, 8 medium, 10 low and 10 informational. 10 of them involve traffic from the internet. Overall score: **49/100** (grade D, weak).

### Fix these first

- **Critical**: Rule allows any source to reach any destination on any port (`policy 3 "WAN-Full-Access"`, VDOM root, risk 60)
- **Critical**: Firmware has a vulnerability that attackers are known to use (`CVE-2024-21762 on FortiOS 7.2.5`, VDOM root, risk 60)
- **Critical**: Firewall management is reachable from the internet (`wan1`, VDOM root, risk 56)
- **Critical**: Rule never takes effect because an earlier rule does the opposite (`policy 5 "Deny-Partner-SSH-shadowed"`, VDOM root, risk 40)
- **High**: Rule allows any source to reach any destination on any port (`policy 2 "Outbound-Any"`, VDOM root, risk 38)
- **High**: Traffic is allowed without any security inspection (`policy 2 "Outbound-Any"`, VDOM root, risk 38)
- **High**: Internet traffic can reach internal services too broadly (`policy 3 "WAN-Full-Access"`, VDOM root, risk 38)
- **High**: Admin accounts without two-factor authentication (`admin, backup_admin, thirdsuper`, VDOM root, risk 35)
- **High**: Admin accounts that can log in from anywhere (`admin, backup_admin`, VDOM root, risk 35)
- **High**: Unencrypted admin access (HTTP or Telnet) (`wan1`, VDOM root, risk 35)

## What the internet can reach

Internet-facing interfaces: wan1.

Published servers (VIPs) and rules that let internet traffic in, with the inspection on each path.

### VDOM `root`

| Reachable at | Lands on | Service | Allowed by | Inspection | SSL |
|---|---|---|---|---|---|
| 203.0.113.10:443/tcp | 10.0.0.50:443 | tcp/443 | rule 1 via VIP WEB_VIP | **none** | n/a |
| from any IPv4 address | any IPv4 address | ALL | rule 3 | **none** | n/a |

**NAT mode** (root: `policy-nat`). In central NAT mode the per-rule NAT setting does nothing and source NAT comes from the central SNAT table.

## What to fix, in order

1. **Rule allows any source to reach any destination on any port** (critical) (3 findings). Replace it with rules for the sources, destinations and services people actually need. If it was added as a temporary fix, remove it.
2. **Firmware has a vulnerability that attackers are known to use** (critical) (2 findings). Upgrade to a fixed release as soon as you can. Until then, turn off or restrict the affected feature and check the firewall for signs of compromise as the advisory describes.
3. **Firewall management is reachable from the internet** (critical). Remove https, http, ssh, telnet and snmp from allowaccess on internet-facing interfaces. If you have to manage over the internet, limit sources with a local-in policy or use a VPN.
4. **Rule never takes effect because an earlier rule does the opposite** (critical). Move this rule above the broader one, or narrow the broader rule so it no longer covers this traffic.
5. **Traffic is allowed without any security inspection** (high) (3 findings). Attach security profiles to the rule, at least IPS and antivirus, and make sure utm-status is enabled.
6. **Internet traffic can reach internal services too broadly** (high). Publish only what must be public, through VIPs. Restrict sources where you can and put IPS on the rule. Admin protocols such as RDP and SSH belong behind a VPN.
7. **Admin accounts without two-factor authentication** (high). Enable two-factor authentication (FortiToken, email or SMS) for every admin, or enforce MFA on the RADIUS or LDAP server that authenticates them.
8. **Admin accounts that can log in from anywhere** (high). Set trusthost entries to your management networks. Trusted hosts only help if every admin account has them, and they don't stop attacks that happen before login, so also restrict the admin interfaces with a local-in policy.
9. **Unencrypted admin access (HTTP or Telnet)** (high). Remove telnet and http from allowaccess on every interface and use SSH and HTTPS only.
10. **Strong cryptography is turned off** (high). Turn it back on: config system global / set strong-crypto enable.
11. **Service reachable from the internet without any inspection** (high) (2 findings). Add IPS to the rule (and antivirus where files are exchanged), use deep inspection if the service uses TLS and you can load its certificate, and limit sources where you can.
12. **SSL-VPN portal open to the internet** (high). Keep the firmware on a fixed release, require MFA, restrict source addresses or countries, and consider moving users to IPsec VPN or ZTNA.
13. **Scanners can't see inside encrypted traffic** (high). Use a deep-inspection SSL/SSH profile on rules where you rely on these scanners, with exemptions for sensitive categories such as banking and health.
14. **Traffic between interfaces in a zone isn't filtered** (high). Set intrazone deny and write rules for the traffic that should flow, or split unrelated networks into separate zones.
15. **Traffic logging is turned off on an allow rule** (medium). Set logtraffic to all, or at least utm.

## Findings

### Critical (4)

#### Rule allows any source to reach any destination on any port

`POLICY_ANY_ANY_ANY` · risk 60/100 · confidence high · internet-facing · VDOM root · `policy 3 "WAN-Full-Access"`

**What we found:** Policy 3 "WAN-Full-Access" allows any source to reach any destination on any service, for traffic coming in from the internet.  
**Why it matters:** Anything that arrives on the rule's interfaces gets through. Segmentation stops at this rule, and an attacker who lands on one side can reach everything on the other.  
**How to fix:** Replace it with rules for the sources, destinations and services people actually need. If it was added as a temporary fix, remove it.

Evidence from the config:

- `config firewall policy / edit 3 (line 150)`
- `wan1 -> dmz; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 4.1; NIST CSF PR.AC-5, PR.PT-3; MITRE ATT&CK T1021; PCI DSS 1.2.1, 1.3.4; ISO 27001 A.8.20, A.8.22

#### Firmware has a vulnerability that attackers are known to use

`FW_KNOWN_EXPLOITED` · risk 60/100 · confidence high · internet-facing · VDOM root · `CVE-2024-21762 on FortiOS 7.2.5`

**What we found:** FortiOS 7.2.5 is affected by CVE-2024-21762 (FG-IR-24-015): an out-of-bounds write in the SSL-VPN daemon that lets an unauthenticated attacker run code on the firewall. The vulnerable code is in SSL-VPN, which is enabled on wan1 here and reachable from the internet. It's in CISA's catalog of known exploited vulnerabilities.  
**Why it matters:** This version is in the affected range of a vulnerability that has been exploited in real attacks, and the feature it lives in is in use here.  
**How to fix:** Upgrade to a fixed release as soon as you can. Until then, turn off or restrict the affected feature and check the firewall for signs of compromise as the advisory describes.

Evidence from the config:

- `CVE-2024-21762 / FG-IR-24-015`
- `SSL-VPN: enabled on wan1`
- `Source: built-in advisory list; confirm on the Fortinet PSIRT site`

Related controls: NIST CSF ID.RA-1, PR.IP-12; MITRE ATT&CK T1190; PCI DSS 6.3.3; ISO 27001 A.8.8

#### Firewall management is reachable from the internet

`IFACE_MGMT_ON_WAN` · risk 56/100 · confidence high · management plane · VDOM root · `wan1`

**What we found:** Interface wan1 faces the internet (it has role wan) and accepts HTTPS, HTTP, SSH and telnet management connections from any address.  
**Why it matters:** The admin login page, SSH or SNMP is open on an internet-facing interface. FortiOS has had several authentication bypass bugs in the admin interface, and exposed management is scanned constantly.  
**How to fix:** Remove https, http, ssh, telnet and snmp from allowaccess on internet-facing interfaces. If you have to manage over the internet, limit sources with a local-in policy or use a VPN.

Evidence from the config:

- `config system interface / edit wan1 (line 30)`
- `allowaccess ping https ssh telnet http`

Related controls: CIS 1.2; NIST CSF PR.AC-5; MITRE ATT&CK T1133; PCI DSS 1.3.1; ISO 27001 A.8.20

#### Rule never takes effect because an earlier rule does the opposite

`POLICY_SHADOW_CONFLICT` · risk 40/100 · confidence high · internal · VDOM root · `policy 5 "Deny-Partner-SSH-shadowed"`

**What we found:** Policy 5 "Deny-Partner-SSH-shadowed" (deny) sits below policy 4 "Allow-Partner-SSH" (accept), and policy 4 already matches every packet policy 5 would. FortiGate uses the first match, so policy 5 never takes effect and the traffic it's meant to block is allowed.  
**Why it matters:** FortiGate stops at the first matching rule. An earlier rule with the opposite action catches all of this rule's traffic, so a block here doesn't block anything, or an allow here never allows anything.  
**How to fix:** Move this rule above the broader one, or narrow the broader rule so it no longer covers this traffic.

Evidence from the config:

- `config firewall policy / edit 5 (line 174)`
- `config firewall policy / edit 4 (line 161)`
- `never reached: internal -> dmz; from 198.51.100.0/24 to 10.0.0.50/32; service tcp/22; action deny`
- `matched first: internal -> dmz; from 198.51.100.0/24 to 10.0.0.0/24; service tcp/22; action accept`

Related controls: CIS 4.1; NIST CSF PR.AC-5; MITRE ATT&CK T1562; PCI DSS 1.2.1; ISO 27001 A.8.20, A.8.9

### High (12)

#### Rule allows any source to reach any destination on any port

`POLICY_ANY_ANY_ANY` · risk 38/100 · confidence high · internet-facing · VDOM root · `policy 2 "Outbound-Any"`

**What we found:** Policy 2 "Outbound-Any" allows any source to reach any destination on any service, for traffic going out to the internet.  
**Why it matters:** Anything that arrives on the rule's interfaces gets through. Segmentation stops at this rule, and an attacker who lands on one side can reach everything on the other.  
**How to fix:** Replace it with rules for the sources, destinations and services people actually need. If it was added as a temporary fix, remove it.

Evidence from the config:

- `config firewall policy / edit 2 (line 138)`
- `internal -> wan1; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 4.1; NIST CSF PR.AC-5, PR.PT-3; MITRE ATT&CK T1021; PCI DSS 1.2.1, 1.3.4; ISO 27001 A.8.20, A.8.22

#### Traffic is allowed without any security inspection

`POLICY_NO_UTM` · risk 38/100 · confidence high · internet-facing · VDOM root · `policy 2 "Outbound-Any"`

**What we found:** Policy 2 "Outbound-Any" allows traffic going out to the internet without any security profile.  
**Why it matters:** No IPS, antivirus, web, DNS or application control looks at this traffic, so malware and exploit attempts pass straight through.  
**How to fix:** Attach security profiles to the rule, at least IPS and antivirus, and make sure utm-status is enabled.

Evidence from the config:

- `config firewall policy / edit 2 (line 138)`
- `internal -> wan1; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 8.1; NIST CSF DE.CM-1, PR.PT-3; MITRE ATT&CK T1190; PCI DSS 11.5; ISO 27001 A.8.7, A.8.16

#### Internet traffic can reach internal services too broadly

`POLICY_WAN_EXPOSURE` · risk 38/100 · confidence high · internet-facing · VDOM root · `policy 3 "WAN-Full-Access"`

**What we found:** Policy 3 "WAN-Full-Access" lets internet traffic reach every service.  
**Why it matters:** A rule from an internet-facing interface opens more than a single published service, or opens remote-access protocols that attackers scan for all day.  
**How to fix:** Publish only what must be public, through VIPs. Restrict sources where you can and put IPS on the rule. Admin protocols such as RDP and SSH belong behind a VPN.

Evidence from the config:

- `config firewall policy / edit 3 (line 150)`
- `wan1 -> dmz; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: NIST CSF PR.AC-5, DE.CM-1; MITRE ATT&CK T1190, T1133; PCI DSS 1.3.1, 1.3.2; ISO 27001 A.8.20, A.8.22

#### Admin accounts without two-factor authentication

`ADMIN_NO_MFA` · risk 35/100 · confidence high · management plane · VDOM root · `admin, backup_admin, thirdsuper`

**What we found:** 3 admin accounts can log in with a password alone: admin, backup_admin, thirdsuper.  
**Why it matters:** A stolen or guessed password is enough to take over the firewall.  
**How to fix:** Enable two-factor authentication (FortiToken, email or SMS) for every admin, or enforce MFA on the RADIUS or LDAP server that authenticates them.

Evidence from the config:

- `config system admin / edit admin (line 15)`
- `config system admin / edit backup_admin (line 20)`
- `config system admin / edit thirdsuper (line 24)`

Related controls: CIS 3.1; NIST CSF PR.AC-7; MITRE ATT&CK T1078; PCI DSS 8.4, 8.5; ISO 27001 A.8.5

#### Admin accounts that can log in from anywhere

`ADMIN_NO_TRUSTED_HOST` · risk 35/100 · confidence high · management plane · VDOM root · `admin, backup_admin`

**What we found:** 2 admin accounts have no trusted hosts and can log in from any address that reaches the admin interface: admin, backup_admin. Because not every account is restricted, trusted hosts don't limit who can reach the login page at all.  
**Why it matters:** Without trusted hosts, anyone who can reach the admin interface can try these accounts' passwords.  
**How to fix:** Set trusthost entries to your management networks. Trusted hosts only help if every admin account has them, and they don't stop attacks that happen before login, so also restrict the admin interfaces with a local-in policy.

Evidence from the config:

- `config system admin / edit admin (line 15)`
- `config system admin / edit backup_admin (line 20)`

Related controls: CIS 3.2; NIST CSF PR.AC-5; PCI DSS 1.3.1; ISO 27001 A.8.20

#### Unencrypted admin access (HTTP or Telnet)

`ADMIN_INSECURE_ACCESS` · risk 35/100 · confidence high · management plane · VDOM root · `wan1`

**What we found:** Telnet, which sends passwords in clear text, is enabled on wan1. HTTP admin access is enabled on wan1. It only redirects to HTTPS, but that first request can be intercepted.  
**Why it matters:** Telnet sends passwords in clear text. HTTP only redirects to HTTPS, but someone on the path can intercept that redirect.  
**How to fix:** Remove telnet and http from allowaccess on every interface and use SSH and HTTPS only.

Evidence from the config:

- `config system interface / edit wan1 (allowaccess includes telnet)`
- `config system interface / edit wan1 (allowaccess includes http)`

Related controls: CIS 1.1; NIST CSF PR.DS-2; MITRE ATT&CK T1040; PCI DSS 2.2.5, 4.2; ISO 27001 A.8.24

#### Strong cryptography is turned off

`HARDEN_WEAK_CRYPTO` · risk 35/100 · confidence high · management plane · VDOM root · `system global`

**What we found:** Strong-crypto is disabled, so the firewall's own HTTPS, SSH and FortiGuard connections may use weak ciphers.  
**Why it matters:** The firewall will accept weak ciphers and old protocols for its own HTTPS, SSH and FortiGuard connections.  
**How to fix:** Turn it back on: config system global / set strong-crypto enable.

Evidence from the config:

- `config system global (line 5)`
- `set strong-crypto disable`

Related controls: CIS 1.3; NIST CSF PR.DS-2; PCI DSS 4.2.1; ISO 27001 A.8.24

#### Service reachable from the internet without any inspection

`EXPOSURE_NAKED_SERVICE` · risk 32/100 · confidence medium · internet-facing · VDOM root · `VIP WEB_VIP via policy 1 "Inbound-Web-VIP"`

**What we found:** VIP WEB_VIP publishes 203.0.113.10:443/tcp to 10.0.0.50:443, and policy 1 "Inbound-Web-VIP" lets the internet reach it (tcp/443). The rule has no security profile, so nothing inspects that traffic.  
**Why it matters:** A server is reachable from the internet and the rule that lets traffic in has no security profile. Exploit attempts reach it untouched, and published servers are among the first things attackers probe.  
**How to fix:** Add IPS to the rule (and antivirus where files are exchanged), use deep inspection if the service uses TLS and you can load its certificate, and limit sources where you can.

Evidence from the config:

- `external: 203.0.113.10:443/tcp`
- `internal: 10.0.0.50:443`
- `service: tcp/443`
- `allowed by: policy 1 "Inbound-Web-VIP"`
- `security profiles: none`
- `SSL inspection: n/a`

Related controls: CIS 8.1; NIST CSF DE.CM-1, PR.AC-5; MITRE ATT&CK T1190; PCI DSS 1.3.1, 11.5; ISO 27001 A.8.7, A.8.20

#### Service reachable from the internet without any inspection

`EXPOSURE_NAKED_SERVICE` · risk 32/100 · confidence medium · internet-facing · VDOM root · `policy 3 "WAN-Full-Access"`

**What we found:** Policy 3 "WAN-Full-Access" lets internet traffic from any IPv4 address reach any IPv4 address on any port. The rule has no security profile, so nothing inspects that traffic.  
**Why it matters:** A server is reachable from the internet and the rule that lets traffic in has no security profile. Exploit attempts reach it untouched, and published servers are among the first things attackers probe.  
**How to fix:** Add IPS to the rule (and antivirus where files are exchanged), use deep inspection if the service uses TLS and you can load its certificate, and limit sources where you can.

Evidence from the config:

- `external: from any IPv4 address`
- `internal: any IPv4 address`
- `service: ALL`
- `allowed by: policy 3 "WAN-Full-Access"`
- `security profiles: none`
- `SSL inspection: n/a`

Related controls: CIS 8.1; NIST CSF DE.CM-1, PR.AC-5; MITRE ATT&CK T1190; PCI DSS 1.3.1, 11.5; ISO 27001 A.8.7, A.8.20

#### SSL-VPN portal open to the internet

`VPN_SSLVPN_WAN_PORTAL` · risk 32/100 · confidence medium · internet-facing · VDOM root · `vpn ssl settings`

**What we found:** SSL-VPN is enabled on wan1, which faces the internet, and the firewall runs FortiOS 7.2.5. Any source address can reach the login page. Web mode is on in portal full-access, which puts more code within reach of the internet.  
**Why it matters:** The FortiGate SSL-VPN has had several critical bugs that let attackers in before login, and they have been exploited at scale. An internet-facing portal needs current firmware and tight controls.  
**How to fix:** Keep the firmware on a fixed release, require MFA, restrict source addresses or countries, and consider moving users to IPsec VPN or ZTNA.

Evidence from the config:

- `config vpn ssl settings (line 250)`
- `source-interface wan1`
- `source-address all`

Related controls: NIST CSF PR.AC-3, ID.RA-1; MITRE ATT&CK T1133, T1190; PCI DSS 6.3.3; ISO 27001 A.8.8, A.8.20

#### Scanners can't see inside encrypted traffic

`POLICY_SSL_INEFFECTIVE_PAYLOAD` · risk 25/100 · confidence high · internal · VDOM root · `policy 4 "Allow-Partner-SSH"`

**What we found:** Policy 4 "Allow-Partner-SSH" relies on IPS and antivirus, but its SSL profile (cert-inspect) only does certificate inspection. Encrypted content passes these scanners unseen.  
**Why it matters:** Antivirus, DLP, file filtering and email filtering need decrypted content. With certificate inspection or no inspection they only see the handshake, so most modern traffic goes unscanned.  
**How to fix:** Use a deep-inspection SSL/SSH profile on rules where you rely on these scanners, with exemptions for sensitive categories such as banking and health.

Evidence from the config:

- `config firewall policy / edit 4 (line 161)`
- `internal -> dmz; from 198.51.100.0/24 to 10.0.0.0/24; service tcp/22; action accept`

Related controls: NIST CSF DE.CM-1; MITRE ATT&CK T1573; ISO 27001 A.8.24

#### Traffic between interfaces in a zone isn't filtered

`ZONE_INTRAZONE_ALLOW` · risk 25/100 · confidence high · internal · VDOM root · `DMZ_ZONE`

**What we found:** Zone 'DMZ_ZONE' has intrazone set to allow, so traffic between its 2 interfaces (dmz, internal) passes without any rule. The policy table won't show it.  
**Why it matters:** With intrazone allow, traffic between the zone's interfaces passes without any rule. If they are different segments there's no segmentation between them, and it won't show up in the policy table.  
**How to fix:** Set intrazone deny and write rules for the traffic that should flow, or split unrelated networks into separate zones.

Evidence from the config:

- `config system zone / edit DMZ_ZONE (line 229)`
- `set intrazone allow`
- `members: dmz, internal`

Related controls: NIST CSF PR.AC-5; MITRE ATT&CK T1021; PCI DSS 1.3.6; ISO 27001 A.8.22

### Medium (8)

#### Traffic logging is turned off on an allow rule

`POLICY_LOGGING_DISABLED` · risk 18/100 · confidence high · internet-facing · VDOM root · `policy 2 "Outbound-Any"`

**What we found:** Policy 2 "Outbound-Any" allows traffic going out to the internet with logging turned off.  
**Why it matters:** Sessions this rule allows leave no record, so there's nothing to look at after an incident.  
**How to fix:** Set logtraffic to all, or at least utm.

Evidence from the config:

- `config firewall policy / edit 2 (line 138)`
- `internal -> wan1; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 7.1; NIST CSF DE.CM-1, PR.PT-1; PCI DSS 10.2; ISO 27001 A.8.15

#### Weak password rules for admins

`ADMIN_WEAK_PASSWORD_POLICY` · risk 17/100 · confidence high · management plane · VDOM root · `system password-policy`

**What we found:** The admin password policy is turned off, so any password is accepted.  
**Why it matters:** Without length and complexity rules, admins can set short passwords that are quick to guess.  
**How to fix:** Enable the admin password policy with a minimum length of 12 and at least two character types (config system password-policy).

Evidence from the config:

- `config system password-policy (line 11)`

Related controls: CIS 2.1; NIST CSF PR.AC-1; PCI DSS 8.3; ISO 27001 A.5.17

#### Several accounts with full super_admin rights

`ADMIN_MULTIPLE_SUPER_ADMIN` · risk 14/100 · confidence medium · management plane · VDOM root · `admin, backup_admin, thirdsuper`

**What we found:** 3 accounts have the super_admin profile: admin, backup_admin, thirdsuper.  
**Why it matters:** Each super_admin account can change anything. The more of them there are, the more ways in, and the harder it is to tell who changed what.  
**How to fix:** Keep super_admin to one or two accounts and give everyone else a profile limited to their job.

Evidence from the config:

- `config system admin / edit admin (line 15)`
- `config system admin / edit backup_admin (line 20)`
- `config system admin / edit thirdsuper (line 24)`

Related controls: NIST CSF PR.AC-4; PCI DSS 7.2; ISO 27001 A.8.2

#### Rule allows any source to reach any destination on any port

`POLICY_ANY_ANY_ANY` · risk 12/100 · confidence high · internal · VDOM root · `policy 9 "DMZ-Intrazone-Traffic"`

**What we found:** Policy 9 "DMZ-Intrazone-Traffic" allows any source to reach any destination on any service, for traffic inside one zone.  
**Why it matters:** Anything that arrives on the rule's interfaces gets through. Segmentation stops at this rule, and an attacker who lands on one side can reach everything on the other.  
**How to fix:** Replace it with rules for the sources, destinations and services people actually need. If it was added as a temporary fix, remove it.

Evidence from the config:

- `config firewall policy / edit 9 (line 217)`
- `dmz, internal -> dmz, internal; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 4.1; NIST CSF PR.AC-5, PR.PT-3; MITRE ATT&CK T1021; PCI DSS 1.2.1, 1.3.4; ISO 27001 A.8.20, A.8.22

#### Traffic is allowed without any security inspection

`POLICY_NO_UTM` · risk 12/100 · confidence high · internal · VDOM root · `policy 9 "DMZ-Intrazone-Traffic"`

**What we found:** Policy 9 "DMZ-Intrazone-Traffic" allows traffic inside one zone without any security profile.  
**Why it matters:** No IPS, antivirus, web, DNS or application control looks at this traffic, so malware and exploit attempts pass straight through.  
**How to fix:** Attach security profiles to the rule, at least IPS and antivirus, and make sure utm-status is enabled.

Evidence from the config:

- `config firewall policy / edit 9 (line 217)`
- `dmz, internal -> dmz, internal; from any IPv4 address to any IPv4 address; service ALL; action accept`

Related controls: CIS 8.1; NIST CSF DE.CM-1, PR.PT-3; MITRE ATT&CK T1190; PCI DSS 11.5; ISO 27001 A.8.7, A.8.16

#### Logs aren't sent off the firewall

`LOG_NO_FORTIANALYZER` · risk 12/100 · confidence high · internal · VDOM root · `remote logging`

**What we found:** No remote log destination is enabled: no FortiAnalyzer, no FortiCloud logging and no syslog server. Logs exist only on the firewall itself.  
**Why it matters:** Logs stay on the device, where space is limited and anyone who takes over the firewall can delete them.  
**How to fix:** Send logs to FortiAnalyzer, FortiAnalyzer Cloud or a syslog/SIEM server.

Evidence from the config:

- `no log fortianalyzer or log syslogd settings are enabled`

Related controls: CIS 7.2; NIST CSF DE.CM-1, PR.PT-1; PCI DSS 10.5; ISO 27001 A.8.15

#### Deep inspection uses the built-in Fortinet CA

`PROFILE_SSL_DEFAULT_CA` · risk 12/100 · confidence high · internal · VDOM root · `deep-default-ca`

**What we found:** SSL/SSH profile 'deep-default-ca' does deep inspection and signs with the factory CA 'Fortinet_CA_SSL'.  
**Why it matters:** Clients have to trust the CA that deep inspection signs with. The factory Fortinet CA isn't part of your PKI and isn't managed by you, which weakens the whole setup.  
**How to fix:** Issue a subordinate CA from your own PKI for SSL inspection and push it to clients.

Evidence from the config:

- `config firewall ssl-ssh-profile / edit deep-default-ca (line 102)`
- `caname Fortinet_CA_SSL`

Related controls: NIST CSF PR.DS-2; ISO 27001 A.8.24

#### IPS sensor only watches, never blocks

`PROFILE_IPS_MONITOR_ONLY` · risk 10/100 · confidence medium · internal · VDOM root · `ips-monitor`

**What we found:** IPS sensor 'ips-monitor' is used by rules, but every signature action in it is monitor or pass. Nothing gets blocked.  
**Why it matters:** Every configured signature action is monitor or pass. Attacks get logged but still reach their target.  
**How to fix:** Set the action to block for high and critical signatures once you've checked for false positives.

Evidence from the config:

- `config ips sensor / edit ips-monitor (line 110)`

Related controls: NIST CSF DE.CM-1, PR.PT-3; ISO 27001 A.8.16

### Low (10)

#### Default 'admin' account still exists

`ADMIN_DEFAULT_NAME` · risk 7/100 · confidence high · management plane · VDOM root · `admin`

**What we found:** The factory account name 'admin' is still in use.  
**Why it matters:** 'admin' is the first username every attacker tries, so keeping it gives away half of the login.  
**How to fix:** Create personal admin accounts, then rename or delete the default 'admin' account.

Evidence from the config:

- `config system admin / edit admin (line 15)`

Related controls: NIST CSF PR.AC-1; ISO 27001 A.5.16

#### Firmware has a vulnerability that attackers are known to use

`FW_KNOWN_EXPLOITED` · risk 6/100 · confidence medium · management plane · VDOM root · `CVE-2024-23113 on FortiOS 7.2.5`

**What we found:** FortiOS 7.2.5 is affected by CVE-2024-23113 (FG-IR-24-029): a format string bug in the FortiManager connection daemon (fgfm) that can be exploited without logging in. The vulnerable code is in FortiManager access (fgfm), which isn't enabled in this backup, so it can't be reached right now. Upgrade anyway: one config change would expose it.  
**Why it matters:** This version is in the affected range of a vulnerability that has been exploited in real attacks, and the feature it lives in is in use here.  
**How to fix:** Upgrade to a fixed release as soon as you can. Until then, turn off or restrict the affected feature and check the firewall for signs of compromise as the advisory describes.

Evidence from the config:

- `CVE-2024-23113 / FG-IR-24-029`
- `FortiManager access (fgfm): no interface allows fgfm access`
- `Source: built-in advisory list; confirm on the Fortinet PSIRT site`

Related controls: NIST CSF ID.RA-1, PR.IP-12; MITRE ATT&CK T1190; PCI DSS 6.3.3; ISO 27001 A.8.8

#### Admin sessions stay open too long

`HARDEN_ADMIN_TIMEOUT` · risk 6/100 · confidence medium · management plane · VDOM root · `system global`

**What we found:** Idle admin sessions time out after 480 minutes. The review's limit is 15 minutes.  
**Why it matters:** An unattended logged-in session can be used by whoever sits down at it or manages to hijack it.  
**How to fix:** Set admintimeout to a short value, such as 5 to 10 minutes.

Evidence from the config:

- `config system global (line 5)`
- `set admintimeout 480`

Related controls: CIS 2.2; NIST CSF PR.AC-7; PCI DSS 8.2.8; ISO 27001 A.8.5

#### Short lockout after failed admin logins

`HARDEN_ADMIN_LOCKOUT` · risk 6/100 · confidence medium · management plane · VDOM root · `system global`

**What we found:** Admin login lockout is weak: the lockout only lasts 60 seconds.  
**Why it matters:** After a few wrong passwords the admin login is only blocked briefly, so password guessing can carry on at a steady pace.  
**How to fix:** Set admin-lockout-threshold to 3 and admin-lockout-duration to 900 seconds or more.

Evidence from the config:

- `config system global (line 5)`
- `admin-lockout-threshold 3`
- `admin-lockout-duration 60`

Related controls: NIST CSF PR.AC-7; MITRE ATT&CK T1110; ISO 27001 A.8.5

#### SSL-VPN uses the factory certificate

`VPN_SSL_DEFAULT_CERT` · risk 6/100 · confidence medium · internet-facing · VDOM root · `vpn ssl settings`

**What we found:** The SSL-VPN portal presents the factory certificate 'Fortinet_Factory'.  
**Why it matters:** Users see a certificate warning every time they connect and learn to click through it. That makes a fake portal much easier to pass off.  
**How to fix:** Install a certificate from a trusted CA for the portal's hostname and set it as servercert.

Evidence from the config:

- `config vpn ssl settings (line 250)`
- `servercert (not set, Fortinet_Factory)`

Related controls: NIST CSF PR.DS-2; ISO 27001 A.8.24

#### Duplicate rule

`POLICY_DUPLICATE` · risk 5/100 · confidence high · internal · VDOM root · `policy 7 "Redundant-Web-B"`

**What we found:** Policy 7 "Redundant-Web-B" is an exact copy of policy 6 "Redundant-Web-A": same traffic, same action, same NAT, inspection and logging. Policy 7 never gets used.  
**Why it matters:** Two rules match exactly the same traffic and treat it the same way. The second one never does anything.  
**How to fix:** Delete the later copy.

Evidence from the config:

- `config firewall policy / edit 7 (line 195)`
- `config firewall policy / edit 6 (line 184)`
- `internal -> dmz; from 192.168.1.0/24 to 10.0.0.50/32; service tcp/443; action accept`

Related controls: ISO 27001 A.8.9

#### Empty address or service group

`OBJ_EMPTY_GROUP` · risk 5/100 · confidence high · internal · VDOM root · `EMPTY_GROUP`

**What we found:** Address group 'EMPTY_GROUP' has no members.  
**Why it matters:** A group without members usually matches nothing, which quietly disables any rule that uses it. That's almost always a mistake.  
**How to fix:** Add the intended members, or remove the group and the rules that use it.

Evidence from the config:

- `config firewall addrgrp / edit EMPTY_GROUP (line 73)`

Related controls: ISO 27001 A.8.9

#### Several address objects for the same network

`OBJ_DUPLICATE_ADDRESS` · risk 5/100 · confidence high · internal · VDOM root · `WEB_SERVER, WEB_SERVER_DUP`

**What we found:** 2 address objects all define 10.0.0.50/32: WEB_SERVER, WEB_SERVER_DUP.  
**Why it matters:** When one network has several names, rules drift apart as people update one object and not the others.  
**How to fix:** Keep one object per network and point all rules at it.

Evidence from the config:

- `config firewall address / edit WEB_SERVER (line 56)`
- `config firewall address / edit WEB_SERVER_DUP (line 59)`

Related controls: ISO 27001 A.8.9

#### Traffic is allowed without any security inspection

`POLICY_NO_UTM` · risk 4/100 · confidence medium · internal · VDOM root · `2 rules in VDOM root`

**What we found:** 2 rules allow narrow internal traffic without any security profile: 6, 7. Each one is low risk on its own, but together they show how much east-west traffic goes uninspected.  
**Why it matters:** No IPS, antivirus, web, DNS or application control looks at this traffic, so malware and exploit attempts pass straight through.  
**How to fix:** Attach security profiles to the rule, at least IPS and antivirus, and make sure utm-status is enabled.

Evidence from the config:

- `policy ids: 6, 7`

Related controls: CIS 8.1; NIST CSF DE.CM-1, PR.PT-3; MITRE ATT&CK T1190; PCI DSS 11.5; ISO 27001 A.8.7, A.8.16

#### No external threat feeds

`HARDEN_THREAT_FEED_MISSING` · risk 3/100 · confidence low · internal · VDOM root · `system external-resource`

**What we found:** No external threat feeds are configured.  
**Why it matters:** Threat feeds let rules block known-bad addresses and domains automatically. Not having one is a missed opportunity rather than a hole.  
**How to fix:** If you have a feed you trust, add it under system external-resource and use it in rules or DNS filtering.

Evidence from the config:

- `config system external-resource has no entries`

Related controls: NIST CSF ID.RA-2, DE.CM-1

### Informational (10)

#### Local administrator accounts

`ADMIN_LOCAL_ACCOUNT` · risk 1/100 · confidence medium · management plane · VDOM root · `admin, backup_admin, thirdsuper`

**What we found:** 3 admin accounts are local to the firewall rather than checked against a central directory: admin, backup_admin, thirdsuper.  
**Why it matters:** Local accounts live only on this firewall. Your central password, MFA and offboarding processes don't reach them, so old accounts tend to linger.  
**How to fix:** Authenticate admins against RADIUS, TACACS+ or LDAP with MFA. Keep a single local break-glass account with a long password stored offline.

Evidence from the config:

- `config system admin / edit admin (line 15)`
- `config system admin / edit backup_admin (line 20)`
- `config system admin / edit thirdsuper (line 24)`

Related controls: NIST CSF PR.AC-1; PCI DSS 8.2; ISO 27001 A.5.16

#### Disabled rules left in the policy table

`POLICY_DISABLED` · risk 1/100 · confidence high · internal · VDOM root · `1 rule in VDOM root`

**What we found:** Rule 8 is disabled but still in the table.  
**Why it matters:** Old disabled rules slow down reviews and can be switched back on by accident.  
**How to fix:** Delete disabled rules you no longer need. If you keep one on purpose, say why in its comment.

Evidence from the config:

- `policy ids: 8`

Related controls: ISO 27001 A.8.9

#### Rules without a comment

`POLICY_NO_COMMENT` · risk 1/100 · confidence high · internal · VDOM root · `8 rules in VDOM root`

**What we found:** 8 rules have no comment: 1, 2, 3, 4, 5, 6, 7, 9.  
**Why it matters:** Without a comment nobody can tell later why a rule exists or who asked for it.  
**How to fix:** Add a comment with the purpose and the ticket or change number.

Evidence from the config:

- `policy ids: 1, 2, 3, 4, 5, 6, 7, 9`

Related controls: ISO 27001 A.5.37

#### Check this firmware version against Fortinet advisories

`FW_VERSION_REVIEW` · risk 1/100 · confidence high · management plane · VDOM root · `FGVM64 7.2.5 (build 1517)`

**What we found:** The backup is from an FGVM64 running FortiOS 7.2.5 (build 1517). Check it against the current Fortinet PSIRT advisories; this review only knows about issues up to its own release.  
**Why it matters:** Which vulnerabilities apply depends on the exact firmware. An offline review can't know about advisories published after it was written.  
**How to fix:** Look this model and version up on the Fortinet PSIRT site and upgrade to a fixed release if anything applies.

Evidence from the config:

- `#config-version=FGVM64-7.2.5-FW-build1517-230810:opmode=0:vdom=0`

Related controls: NIST CSF ID.RA-1; PCI DSS 6.3.3; ISO 27001 A.8.8

#### No login banner

`HARDEN_LOGIN_BANNER` · risk 1/100 · confidence high · internal · VDOM root · `system global`

**What we found:** No banner is shown before admin login.  
**Why it matters:** A banner tells people that access is monitored and only for authorised users. Some regulations and internal policies require one.  
**How to fix:** Enable pre-login-banner in system global and set the text under config system replacemsg admin.

Evidence from the config:

- `config system global (line 5)`
- `pre-login-banner is not enabled`

Related controls: ISO 27001 A.5.10

#### No high availability

`HA_STANDALONE` · risk 1/100 · confidence low · internal · VDOM root · `system ha`

**What we found:** This firewall runs on its own, without an HA partner.  
**Why it matters:** If this unit fails, traffic stops until it's replaced. That can be a sensible choice for a small site.  
**How to fix:** If this firewall carries production traffic, consider an HA pair.

Evidence from the config:

- `config system ha is at its defaults`

Related controls: NIST CSF PR.IP-4; ISO 27001 A.8.14

#### Unused address objects

`OBJ_UNUSED_ADDRESS` · risk 1/100 · confidence medium · internal · VDOM root · `2 address objects in VDOM root`

**What we found:** 2 address objects in VDOM root are not referenced anywhere this review looks (rules, groups, routes, VPN and SD-WAN settings): UNUSED_HOST, WEB_SERVER_DUP.  
**Why it matters:** Objects that nothing references clutter the configuration and are easy to reuse by mistake.  
**How to fix:** Delete them after checking that nothing outside this firewall (FortiManager, scripts) depends on them.

Evidence from the config:

- `config firewall address / edit WEB_SERVER_DUP (line 59)`
- `config firewall address / edit UNUSED_HOST (line 62)`

Related controls: ISO 27001 A.8.9

#### Unused custom services

`OBJ_UNUSED_SERVICE` · risk 1/100 · confidence medium · internal · VDOM root · `1 custom service in VDOM root`

**What we found:** 1 custom service in VDOM root is not referenced anywhere this review looks (rules, groups, routes, VPN and SD-WAN settings): TCP_8080.  
**Why it matters:** Custom services that nothing references are clutter.  
**How to fix:** Delete custom services you no longer need.

Evidence from the config:

- `config firewall service custom / edit TCP_8080 (line 78)`

Related controls: ISO 27001 A.8.9

#### Address objects that overlap

`OBJ_OVERLAPPING_SUBNET` · risk 1/100 · confidence medium · internal · VDOM root · `DMZ_NET / WEB_SERVER`

**What we found:** 'WEB_SERVER' (10.0.0.50/32) sits inside 'DMZ_NET' (10.0.0.0/24).  
**Why it matters:** One network sits inside another under a different name. That's often fine, but it can hide conflicting intent.  
**How to fix:** Check the pair and remove whichever one is left over, if any.

Evidence from the config:

- `config firewall address / edit DMZ_NET (line 53)`
- `config firewall address / edit WEB_SERVER (line 56)`

#### Address objects that overlap

`OBJ_OVERLAPPING_SUBNET` · risk 1/100 · confidence medium · internal · VDOM root · `DMZ_NET / WEB_SERVER_DUP`

**What we found:** 'WEB_SERVER_DUP' (10.0.0.50/32) sits inside 'DMZ_NET' (10.0.0.0/24).  
**Why it matters:** One network sits inside another under a different name. That's often fine, but it can hide conflicting intent.  
**How to fix:** Check the pair and remove whichever one is left over, if any.

Evidence from the config:

- `config firewall address / edit DMZ_NET (line 53)`
- `config firewall address / edit WEB_SERVER_DUP (line 59)`

## What this review covered

9 areas were checked, 3 were read only to see which objects are in use, and 0 were present but not read.

- Unused-object results cover rules of every kind, groups, routes, VPN and SD-WAN settings. Objects used only by FortiManager, scripts or runtime state can still show up as unused, so check before deleting.
- This looks like a normal backup, which leaves out every setting that is at its factory default. The review reads a missing setting as the FortiOS default.
- No hit counters were given (--hit-counts), so rules that are enabled but never used can't be found.

---
_Made by fgaudit 2.1.0. This is an offline review of a configuration file; nothing was scanned or tested on the device. Check each finding against how the network is really used before you change anything._
