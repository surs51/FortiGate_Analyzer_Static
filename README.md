# fgaudit

fgaudit reads a FortiGate configuration backup and tells you what's risky in it.

It runs on your own machine, needs nothing but Python, and never connects to the firewall or to the internet. You give it a file, you get a report.

<img width="893" height="802" alt="Screenshot 2026-09-23 102041" src="https://github.com/user-attachments/assets/1601c308-cf78-4b73-87ac-ff96fef376e8" />

## Getting a backup to review

```bash
python fgaudit.py my-firewall.conf
```

That writes `my-firewall.html` into the current folder. Open it in a browser.

Any plain-text FortiGate backup works:

- **From the GUI:** click your user name in the top right, then *Configuration* > *Backup*. Save to your computer and leave encryption off. fgaudit can't read password-protected backups and will tell you if you give it one.
- **From the CLI:** run `show full-configuration` over SSH and save the output to a file.

A normal backup leaves out every setting that's still at its factory default. fgaudit knows the FortiOS defaults and reads a missing setting as its default, so both kinds of file give the same results. The report notes it when it's reading a normal backup.

Keep in mind that a backup holds passwords, VPN keys and your whole network layout. Treat the file, and the reports, as confidential.

## What it checks

**Firewall rules.** fgaudit doesn't judge rules by the names of their objects. It works out which addresses, ports and interfaces each rule really covers, following groups, group exclusions, zones, SD-WAN zones, negated fields and VIPs, and then reasons about those. An address object called `Internal_Server` that actually contains `0.0.0.0/0` is treated as what it is. With that it finds:

- rules that allow any source to any destination on any service, and rules that are wide on one or two of those;
- rules that can never match because an earlier rule already catches their traffic. If the earlier rule does the opposite, the later one is reported as critical: a block that doesn't block, or an allow that never allows;
- block rules that are partly bypassed by an earlier allow;
- block rules that don't apply to published servers because `match-vip` is off, a common reason a country block list doesn't protect a web server;
- rules where the security profiles look configured but never run, whether shadowed, switched off with `utm-status disable`, or blind to HTTPS because the SSL profile doesn't decrypt;
- duplicates, near-duplicates, rules on expired one-time schedules, rules without logging, and (if you give it hit counters) rules that nobody uses.

**What the internet can reach.** The report includes a table of every path in from the internet: each published server (VIP) and each rule from an internet-facing interface, what it lands on, which ports actually get through, and which inspection profiles sit on the path. It understands port forwarding, load-balancer VIPs, VIP groups, central NAT and policy NAT. It leaves out paths that an earlier deny rule already blocks.

**Management access.** Admin protocols on internet-facing interfaces, with local-in policies taken into account (Fortinet's own advice for limiting the admin interface), admins without MFA or trusted hosts, the default `admin` account, wildcard remote admins, API users with too much access, Telnet and HTTP access, and weak password and lockout settings.

**VPN.** IKEv1, aggressive mode with a pre-shared key, weak Diffie-Hellman groups and ciphers, phase 2 without PFS or replay protection, an SSL-VPN portal open to the internet, old TLS, the factory certificate, no login lockout, split tunnelling, VPN users without MFA, and rules that let VPN users reach everything.

**Firmware.** The version is always shown so you can check it against Fortinet's advisories. On top of that, fgaudit knows which older FortiOS branches no longer get security fixes. It also carries a short built-in list of vulnerabilities that attackers are known to use (CVE-2018-13379, CVE-2022-42475, CVE-2023-27997, CVE-2024-21762, CVE-2022-40684, CVE-2024-55591 and CVE-2024-23113). It only raises them as critical when the affected feature is actually enabled and reachable from the internet in your config.

**Everything else.** Security profiles that watch but don't block, deep inspection with the factory CA or with certificate checks set to `ignore`, web and DNS filters that let phishing and malware sites through, logs that never leave the box or go out as plain UDP, short log retention, HA without heartbeat protection, SNMP with default communities, plain-text LDAP, `private-data-encryption` left off (which matters if your backups get around), asymmetric routing, anti-spoofing turned off, zones that pass traffic without rules, and housekeeping such as unused and duplicate objects and empty groups.

Each finding is mapped to the CIS FortiGate Benchmark, NIST CSF, MITRE ATT&CK, PCI DSS and ISO 27001 where that makes sense. Treat the mappings as a starting point for an audit, not a verdict.

## How it decides what faces the internet

A lot depends on knowing which interfaces are internet links, and interface names aren't reliable. fgaudit looks for real evidence, in this order:

1. interfaces you name with `--wan`;
2. `set role wan`;
3. interfaces that carry the default route, including through SD-WAN zones;
4. DHCP or PPPoE uplinks that take a default gateway from the provider;
5. public addresses on interfaces and SD-WAN member links.

Only if none of that exists does it fall back to guessing from names like `wan1` or `outside`, and it says so in the report. The interfaces it settled on are listed at the top of the exposure section. If they're wrong, run it again with `--wan`.

## Reading the report

The HTML report opens with a score and a short summary, then a few charts and the handful of things to fix first. Below that are the exposure table, a fix-it list ordered by severity, a section on what was and wasn't covered, and a searchable list of every finding. Click a finding for the details and the config lines behind it.

- **Severity** is how bad the problem is if it's real: critical, high, medium, low or informational.
- **Confidence** says how sure the check is. It's low when, for example, fgaudit had to guess which interface faces the internet.
- **Risk score** (0 to 100) combines severity, confidence and exposure. A problem reachable from the internet scores higher than the same problem between two internal networks.
- **Overall score** starts at 100 and drops a little for every finding, more for serious ones. A confident critical finding caps it at 49 (grade D) and a confident high one at 79, so a firewall with one exploitable hole can't look healthy just because everything else is tidy.

<img width="857" height="805" alt="Screenshot 2026-09-23 101958" src="https://github.com/user-attachments/assets/f476a620-1be3-4987-a7ac-e145219bd8a6" />


## Options

```
fgaudit CONFIG [options]
```

| Option | What it does |
| --- | --- |
| `--html`, `--json`, `--csv`, `--sarif`, `--md` | Write that format. Each takes an optional file path. |
| `--all-formats` | Write all five. |
| `-o DIR`, `--name NAME` | Where to write the reports, and what to call them. |
| `--stdout-format FORMAT` | Print JSON, CSV, SARIF or Markdown to the screen instead. |
| `--wan IFACE ...` | Treat these interfaces as internet-facing. |
| `--min-severity LEVEL` | Leave out findings below this severity. |
| `--vdom VDOM ...` | Only report these VDOMs. |
| `--fail-on LEVEL` | Exit with code 1 if anything at this severity or worse is found. |
| `--hit-counts FILE` | Rule hit counters, to find rules that are never used. |
| `--psirt-feed FILE` | Your own advisory list to match the firmware against. |
| `--diff OTHER` | Compare the rules in two backups instead of reviewing. |
| `--lookup SPEC` | Ask which rule a packet would hit instead of reviewing. |
| `-v`, `-vv` | Show progress, or debug output. |

Thresholds such as the admin timeout limit or the size at which a policy table counts as very large can be changed too. `fgaudit --help` lists them.

Exit codes: 0 means it ran, 1 means `--fail-on` was triggered, 2 means the file couldn't be read or isn't a FortiGate config.

## Other things it can do

**Compare two backups.** `fgaudit old.conf --diff new.conf` lists the rules that were added, removed or changed, field by field. It's handy for reviewing a change window or spotting changes nobody announced.

**Trace a packet.** `fgaudit fw.conf --lookup wan1,203.0.113.9,dmz,10.0.0.50,tcp,443` walks the rule table from the top the way the firewall does, and tells you which rule would match and what inspection applies. It knows about VIPs, so the service is checked against the port after translation. It also warns you when an earlier rule might match but depends on something that can't be worked out offline, such as an FQDN object, a country, or a logged-in user.

**Find unused rules.** Export your rule hit counters however suits you and save them as JSON, either `{"12": 5321, "13": 0}` or, with VDOMs, `{"root": {"12": 5321}}`. Pass the file with `--hit-counts`. Enabled rules with zero hits get reported. Make sure the counters cover a normal business cycle first.

**Match your own advisories.** If you keep a list of advisories per model and version, pass it with `--psirt-feed` as `{"FG100F": {"7.2.5": ["FG-IR-24-015 ..."]}}`. Nothing is ever downloaded; the file is only read.

**Run it in CI.** For example, fail a pipeline on anything high or worse and upload SARIF to GitHub code scanning:

```bash
python fgaudit.py fw.conf --sarif results.sarif --fail-on high
```

**Use it from Python.**

```python
from fgaudit import run_audit

result = run_audit(open("fw.conf", encoding="utf-8").read(), wan_interfaces=["wan1"])
print(result.summary.overall_score)
for finding in result.findings:
    print(finding.severity.label, finding.rule_id, finding.description)
```

## Installing

You don't have to install anything. With Python 3.10 or newer, run it straight from the folder:

```bash
python fgaudit.py fw.conf
```

The `fgaudit.sh` and `fgaudit.bat` wrappers do the same thing. To carry it around as a single file, for example on a jump host, build a zipapp:

```bash
python -m zipapp src -m "fgaudit.cli:main" -o fgaudit.pyz -c
```

Then run it with `python fgaudit.pyz fw.conf`. If you'd rather have an `fgaudit` command on your PATH, use `pip install .`.

## What it can't do

- It reads a file. It doesn't see sessions, routing tables, certificate expiry, license status or anything else that only exists on the running device.
- A rule is reported as shadowed only when a single earlier rule covers it. Coverage by a combination of several earlier rules isn't checked, on purpose, to avoid false alarms.
- FQDN addresses, countries, internet service database entries and dynamic objects have no fixed addresses. fgaudit never claims a shadow or an overlap it can't prove from them, so it may miss some.
- The built-in vulnerability list is short and dated. It only covers well-known vulnerabilities that were exploited in the wild, as of this release. Always check the Fortinet PSIRT site for your exact version.
- Defaults are those of current FortiOS releases. Very old firmware used different defaults in a few places, and fgaudit only adjusts for the ones it knows about.
- Local-in policies are taken into account for IPv4 management access only.
- NGFW policy-mode security rules, ZTNA and access-proxy settings are only read to see which objects they use. Their own risks aren't checked.
- It's a tool to support your judgement, not a replacement for it. Check a finding against how the network is really used before you change a production firewall.

`tests/fixtures/broken_config.conf` is a small config with many deliberate mistakes. `examples/broken-sample.*` shows what fgaudit reports for it.

The code is laid out like this:

- `parser/` turns the backup into a tree of objects;
- `object_resolver/` works out what each object and rule really covers, which interfaces face the internet, and where every object is used;
- `analyzers/` holds one module per area, and each one produces findings;
- `rules/catalog.py` holds the title, explanation, fix and compliance mapping for every finding;
- `knowledge.py` holds FortiOS facts such as defaults, support dates and known vulnerabilities;
- `reporting/` holds one module per output format.

To add a check, give it an entry in `rules/catalog.py`, then call `ctx.finding("YOUR_RULE_ID", ...)` from an analyzer. All the report formats pick it up automatically. A new analyzer module also needs to be imported in `analyzers/__init__.py`.
