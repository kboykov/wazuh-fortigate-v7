# wazuh-fortigate-v7

Wazuh decoders and detection rules for **FortiGate firewalls running FortiOS 7.x**.

Covers all major FortiGate log categories — traffic, IPS, AV, application control, web filter, DNS, VPN, email filter, DLP, SSH, SSL, WAF, anomaly detection, and system events — with proper Wazuh alert levels mapped to FortiGate severity.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [How It Works](#how-it-works)
- [FortiGate Configuration](#fortigate-configuration)
- [Wazuh Installation](#wazuh-installation)
- [File Reference](#file-reference)
- [Decoder Architecture](#decoder-architecture)
- [Rule Architecture](#rule-architecture)
- [Alert Level Mapping](#alert-level-mapping)
- [Log Categories and Groups](#log-categories-and-groups)
- [Log ID Structure](#log-id-structure)
- [Covered Log IDs](#covered-log-ids)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)

---

## Overview

FortiGate firewalls emit structured key=value logs across dozens of event types. This project provides:

- **738 decoders** — extract every FortiGate log field into named Wazuh fields
- **1387 rules** — match specific FortiGate log IDs and assign alert levels proportional to severity

Built against the **FortiOS 7.0, 7.2, and 7.4 Log Reference** and cross-validated against FortiOS 7.4.4 documentation for log ID format and field structure.

---

## Requirements

| Component | Minimum version |
|---|---|
| FortiOS | 7.0 |
| Wazuh Manager | 4.x |
| Wazuh Agent | Not required — uses syslog ingestion |

---

## How It Works

```
FortiGate Firewall
       │
       │  syslog UDP/TCP (raw key=value format)
       ▼
Wazuh Manager (syslog listener)
       │
       │  strips RFC 3164 header, passes message to decoders
       ▼
fortinet-fortigate-firewall  ← prematch decoder
       │
       │  matches: ^date=YYYY-MM-DD time=HH:MM:SS devname="..." devid="..." ...
       ▼
fortinet-fortigate-fields-v7  ← 737 child decoders (one per field)
       │
       │  each extracts one field: action, srcip, dstip, logid, etc.
       ▼
Wazuh Rules (100010 → 100010–101396)
       │
       │  match decoded logid field against known FortiGate log IDs
       ▼
Wazuh Alert (level 3–12 based on severity)
```

FortiGate logs in raw syslog format look like:

```
date=2024-03-15 time=10:22:41 devname="fw-edge" devid="FG100F0000000001" eventtime=1710498161 tz="+0000" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" user="admin" ui="ssh(192.168.1.100)" status="failed" reason="User does not exist"
```

The prematch decoder identifies this as a FortiGate log. The 737 child decoders each extract one named field. Rules then fire based on the decoded `logid` field value.

---

## FortiGate Configuration

### 1. Enable syslog output

In the FortiGate CLI:

```
config log syslogd setting
    set status enable
    set server <WAZUH_MANAGER_IP>
    set port 514
    set facility local7
    set format default
    set reliable disable
end
```

> **Format must be `default`** (raw key=value). The CEF and CSV formats use a different structure and will not match the decoders.

### 2. Configure log source filtering (optional but recommended)

```
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic enable
    set sniffer-traffic disable
    set anomaly enable
    set voip enable
end
```

### 3. Verify log output

From FortiGate CLI, confirm logs are being sent:

```
diagnose log test
```

From the Wazuh manager, confirm reception:

```bash
tcpdump -i any -n port 514 -A | grep "devname="
```

---

## Wazuh Installation

### 1. Configure Wazuh syslog listener

Add a UDP syslog listener to `/var/ossec/etc/ossec.conf` on the Wazuh Manager:

```xml
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>
</ossec_config>
```

> Use `<protocol>tcp</protocol>` if FortiGate is configured with `set reliable enable`.

### 2. Install the decoders

```bash
cp 0100-fortigate_decoders.xml /var/ossec/etc/decoders/
chown root:wazuh /var/ossec/etc/decoders/0100-fortigate_decoders.xml
chmod 640 /var/ossec/etc/decoders/0100-fortigate_decoders.xml
```

### 3. Install the rules

```bash
cp 0391-fortigate_rules.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/rules/0391-fortigate_rules.xml
chmod 640 /var/ossec/etc/rules/0391-fortigate_rules.xml
```

### 4. Test the configuration

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a sample FortiGate log line and verify the decoder and rule fire correctly. Expected output:

```
**Phase 1: Completed pre-decoding.

**Phase 2: Completed decoding.
        name: 'fortinet-fortigate-fields-v7'
        devname: 'fw-edge'
        logid: '0100032002'
        type: 'event'
        ...

**Phase 3: Completed filtering (rules).
        id: '100365'
        level: '10'
        description: 'Admin login failed'
        groups: ['fortigate', 'fortios.event.event', 'fortios.category.system', 'fortios.severity.alert']
```

### 5. Restart Wazuh Manager

```bash
systemctl restart wazuh-manager
```

---

## File Reference

| File | Description |
|---|---|
| `0100-fortigate_decoders.xml` | All 738 FortiGate decoders |
| `0391-fortigate_rules.xml` | All 1387 FortiGate rules |

The file numbering follows Wazuh convention: decoders below `0500` load before most built-in decoders; rules in the `100000+` range are the custom rule space.

---

## Decoder Architecture

### Root decoder

```xml
<decoder name="fortinet-fortigate-firewall">
  <prematch type="pcre2">^date=\d{4}-\d{2}-\d{2}\s+time=\d{2}:\d{2}:\d{2}\s+devname="[^"]*"\s+devid="[^"]*"\s+eventtime=\d+\s+tz="[^"]*"\s+logid="\d+"</prematch>
</decoder>
```

The root decoder uses a PCRE2 prematch that anchors to the start of the line and requires six mandatory FortiOS 7.x header fields in order. Any log that does not match this pattern is ignored entirely.

This prematch is **specific to FortiOS 7.x**. FortiOS 6.x omits `devname`, `devid`, `eventtime`, and `tz` from the syslog header — those logs will not match.

### Field decoders

Each of the 737 child decoders extracts exactly one field. The pattern handles three cases the field can appear in:

```xml
<decoder name="fortinet-fortigate-fields-v7">
  <parent>fortinet-fortigate-firewall</parent>
  <regex>\s+action="(\.*)"|\s+action=(\.*)\s|\s+action=(\.*)$</regex>
  <order>action</order>
</decoder>
```

| Alternative | Matches | Example |
|---|---|---|
| `\s+field="(\.*)"`  | quoted value | `action="accept"` |
| `\s+field=(\.*)\s` | unquoted value followed by space | `proto=6 ` |
| `\s+field=(\.*)$` | unquoted value at end of line | `sentbyte=1024` |

In Wazuh's OSdec regex engine, `\.` matches any single character. Each alternative has one capture group; whichever alternative fires provides the value mapped to the `<order>` field name. All three alternatives are mutually exclusive in practice because FortiGate consistently quotes strings and leaves numbers unquoted.

### Extracted fields (partial list)

`action`, `app`, `appcat`, `appid`, `attack`, `attackid`, `catdesc`, `countdrop`, `dstcountry`, `dstintf`, `dstip`, `dstport`, `duration`, `eventtype`, `hostname`, `level`, `logdesc`, `logid`, `msg`, `policyid`, `policyname`, `profile`, `proto`, `rcvdbyte`, `sentbyte`, `service`, `sessionid`, `srcintf`, `srcip`, `srcport`, `status`, `subtype`, `trandisp`, `transip`, `transport`, `type`, `url`, `user`, `vd`, `virus`, and 680+ more.

---

## Rule Architecture

### Parent rule

```xml
<rule id="100010" level="4">
    <decoded_as>fortinet-fortigate-firewall</decoded_as>
    <description>Fortigate messages grouped</description>
</rule>
```

All other rules use `<if_sid>100010</if_sid>` as their parent. This ensures FortiGate rules only fire after the FortiGate decoder has matched.

### Log ID matching

Rules match the decoded `logid` field using a trailing `$` anchor against the 6-digit message ID component:

```xml
<rule id="100365" level="10">
    <if_sid>100010</if_sid>
    <field name="logid">032002$</field>
    <description>Admin login failed</description>
    <group>fortios.event.event,fortios.category.system,fortios.severity.alert</group>
</rule>
```

**Why a trailing `$` rather than exact match:** FortiOS 7.x log IDs are 10-digit zero-padded strings (e.g., `logid="0100032002"`). The first four digits encode the log category and subtype; the last six digits are the unique message ID. Matching only the six-digit suffix correctly identifies the event regardless of which category prefix FortiGate emits, and remains valid if Fortinet ever adjusts category encoding across minor versions.

---

## Alert Level Mapping

Wazuh alert levels are assigned based on the FortiGate severity embedded in the rule's `<group>` tag:

| FortiGate severity | Wazuh level | Meaning |
|---|---|---|
| `debug` / `information` | 3 | Informational — logged but no alert |
| `notice` | 4 | Normal operational events |
| `warning` | 6 | Conditions worth watching |
| `error` | 8 | Functional errors |
| `critical` / `alert` | 10 | Security or operational incidents |
| `emergency` | 12 | Critical system failure |

> Wazuh's default alert threshold is **level 7**. Events at level 3 and 4 are indexed but do not generate alerts unless the threshold is lowered. Adjust `<alert_level>` in `ossec.conf` to change this.

### High-value alert examples

| Rule ID | LogID | Description | Level |
|---|---|---|---|
| 100011 | `018432$` | Attack detected by UDP/TCP anomaly | 10 |
| 100012 | `018433$` | Attack detected by ICMP anomaly | 10 |
| 100056 | `020010$` | Kernel error | 10 |
| 100365 | `032002$` | Admin login failed | 10 |
| 100380 | `032021$` | Admin login disabled | 10 |
| 100417 | `032102$` | Configuration changed | 10 |
| 101101 | `016384$` | IPS signature attack (TCP/UDP) | 10 |
| 101102 | `016385$` | IPS signature attack (ICMP) | 10 |
| 100377 | `032018$` | FIPS CC entered error mode | 12 |
| 100391 | `032032$` | DLP archive full | 12 |
| 100392 | `032033$` | Quarantine disk full | 12 |

---

## Log Categories and Groups

Each rule assigns Wazuh groups in the format `fortios.event.<type>,fortios.category.<subtype>,fortios.severity.<level>`.

| Event type | Group prefix | Examples |
|---|---|---|
| Traffic | `fortios.event.traffic` | forward, local, snat, dnat |
| IPS | `fortios.event.ips` | signature, anomaly, botnet |
| Antivirus | `fortios.event.virus` | infected, scanerror, oversize |
| Application control | `fortios.event.app-ctrl` | signature, port-violation |
| Web filter | `fortios.event.webfilter` | ftgd_blk, urlfilter, antiphishing |
| DNS filter | `fortios.event.dns` | dns-query, dns-response |
| Email filter | `fortios.event.emailfilter` | spam, bannedword, webmail |
| DLP | `fortios.event.dlp` | dlp, dlp-docsource |
| VPN | `fortios.event.event` (category: vpn) | tunnel-up, tunnel-down |
| SSH | `fortios.event.ssh` | ssh-command, ssh-channel |
| SSL | `fortios.event.ssl` | ssl-anomaly, ssl-handshake |
| WAF | `fortios.event.waf` | waf-signature, waf-http-constraint |
| System events | `fortios.event.event` (category: system) | login, config-change, ha |
| Anomaly | `fortios.event.anomaly` | tcp/udp, icmp |

These groups can be used in Wazuh to build dashboards, filters, and integrations (e.g., send all `fortios.event.ips` events to a SIEM or ticketing system).

---

## Log ID Structure

FortiOS 7.x log IDs are 10-digit zero-padded decimal numbers with this structure:

```
0  1  0  0  0  3  2  0  0  2
│  │  │  │  └──────────────┘
│  │  │  │   Message ID (6 digits)
│  │  └──┘
│  │   Subtype ID (2 digits)
└──┘
 Category ID (2 digits)
```

| Category ID | Log type | `type=` field |
|---|---|---|
| 00 | Traffic | `traffic` |
| 01 | System events | `event` |
| 02 | Antivirus | `utm` (subtype=virus) |
| 03 | Web filter | `utm` (subtype=webfilter) |
| 04 | IPS | `utm` (subtype=ips) |
| 05 | Email filter | `utm` (subtype=emailfilter) |
| 07 | Anomaly | `utm` (subtype=anomaly) |
| 08 | VoIP | `utm` (subtype=voip) |
| 09 | DLP | `utm` (subtype=dlp) |
| 10 | Application control | `utm` (subtype=app-ctrl) |
| 12 | WAF | `utm` (subtype=waf) |
| 14 | GTP | `gtp` |
| 15 | DNS | `dns` |
| 16 | SSH | `utm` (subtype=ssh) |
| 17 | SSL | `utm` (subtype=ssl) |
| 19 | File filter | `utm` (subtype=file-filter) |
| 20 | ICAP | `utm` (subtype=icap) |

---

## Covered Log IDs

### Anomaly (07xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 100011 | 018432 | TCP/UDP anomaly attack | 10 |
| 100012 | 018433 | ICMP anomaly attack | 10 |
| 100013 | 018434 | Other anomaly attack | 10 |

### Application Control (10xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 100014–100020 | 028672–028678 | IM application events | 3 |
| 100021 | 028704 | IPS/app control pass | 3 |
| 100022 | 028705 | IPS/app control block | 6 |
| 100023 | 028706 | IPS/app control reset | 6 |
| 100024 | 028720 | SSH application pass | 3 |
| 100025 | 028721 | SSH application block | 6 |
| 100026 | 028736 | Port enforcement | 6 |
| 100027 | 028737 | Protocol enforcement | 6 |

### DLP (09xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 100028 | 024576 | DLP sensor rule violation (warning) | 6 |
| 100029 | 024577 | DLP sensor rule violation (notice) | 4 |
| 100030 | 024578 | DLP fingerprint document source | 4 |
| 100031 | 024579 | DLP fingerprint document error | 6 |

### DNS Filter (15xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 100032 | 054000 | DNS query | 3 |
| 100033 | 054200 | DNS resolution error | 8 |
| 100034 | 054400 | Domain blocked (domain-filter list) | 6 |
| 100035 | 054401 | Domain allowed (domain-filter list) | 3 |
| 100036 | 054600 | Domain blocked — botnet C&C (IP) | 6 |
| 100037 | 054601 | Domain blocked — botnet C&C (domain) | 6 |
| 100038–100043 | 054800–054805 | FortiGuard DNS rating events | 3–4 |

### Email Filter (05xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 100044 | 020480 | Spam notification | 4 |
| 100045 | 020481 | Email message | 3 |
| 100046 | 020482 | Banned word notification | 4 |
| 100047 | 020509 | FortiGuard error | 4 |
| 100048 | 020510 | Webmail message | 3 |

### IPS (04xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| 101101 | 016384 | Attack — TCP/UDP signature | 10 |
| 101102 | 016385 | Attack — ICMP signature | 10 |
| 101103 | 016386 | Attack — other signature | 10 |
| 101104 | 016399 | Malicious URL detected | 10 |
| 101105 | 016400 | Botnet C&C warning | 10 |
| 101106 | 016401 | Botnet C&C notification | 4 |

### Antivirus (02xx)

Rules cover 87 AV-specific log IDs in the 008192–009240 message range including:
- Infected file detected/blocked
- Oversize file
- Filename block
- Scan errors (memory, timeout, corrupted archive)
- FortiNDR/FortiAI events
- Analytics submission events
- Content disarm (CDR)
- Inline sandbox events

### System Events (01xx)

Covers 700+ event log IDs including:

- Admin login success/failure/lockout
- Configuration changes
- HA failover and sync
- Interface up/down
- Memory conserve mode enter/exit
- VPN tunnel up/down
- DHCP lease events
- NTP sync events
- Certificate management
- License expiry warnings
- FIPS/CC error modes

### Traffic (00xx)

| Rule | Log ID | Description | Level |
|---|---|---|---|
| (various) | 000002 | Forward traffic allowed | 3 |
| (various) | 000013 | Forward traffic session close | 3 |

---

## Troubleshooting

### Logs are not being received by Wazuh

1. Verify the FortiGate syslog server IP and port match the Wazuh listener:
   ```
   diagnose log test
   ```
2. Check that Wazuh's syslog port is open:
   ```bash
   ss -ulnp | grep 514
   ```
3. Check firewall rules between FortiGate and Wazuh Manager.

### Logs are received but the decoder does not fire

Use `wazuh-logtest` to test a log line interactively:

```bash
/var/ossec/bin/wazuh-logtest
```

Common causes:
- **FortiOS version is 6.x** — the prematch requires `devname`, `devid`, `eventtime`, and `tz` fields which are absent in 6.x logs.
- **Syslog format is not `default`** — CEF format uses a completely different structure. Verify with `show log syslogd setting` on the FortiGate.
- **A syslog relay is adding a second RFC 3164 header** — if logs pass through a syslog aggregator that re-wraps them, the message content may be shifted. Check the raw bytes with `tcpdump`.

### A rule fires on the wrong log

If a rule is matching a FortiGate log it should not match, add a `<field name="type">` or `<field name="subtype">` filter to narrow the match:

```xml
<rule id="100365" level="10">
    <if_sid>100010</if_sid>
    <field name="logid">032002$</field>
    <field name="type">^event$</field>
    <field name="subtype">^system$</field>
    <description>Admin login failed</description>
    <group>fortios.event.event,fortios.category.system,fortios.severity.alert</group>
</rule>
```

### Alerts are not generating for high-severity events

The default Wazuh alert threshold is level 7. Events at level 3 and 4 are indexed but suppressed. To lower the threshold, edit `/var/ossec/etc/ossec.conf`:

```xml
<alerts>
    <log_alert_level>3</log_alert_level>
</alerts>
```

Alternatively, add specific email or integration actions for level 10+ events only.

---

## Known Limitations

**Log IDs not covered:**

- `logid 000001` (local traffic allowed — session start alternate) is absent; traffic rules begin at 000002.
- HA (high availability) failover events have limited coverage.
- IPS sub-type log IDs 016387–018431 are not individually mapped; only the six most common IPS event types are present.
- Event log ID gaps: 020009, 020011–020015 are absent from the FortiOS log reference and are intentionally not covered.

**FortiOS version compatibility:**

- Designed and tested against **FortiOS 7.0, 7.2, and 7.4**.
- FortiOS 6.x logs use a different header field order and will not match the root decoder prematch.
- FortiOS 7.6+ log IDs should remain compatible but have not been validated.

**Log ID suffix matching:**

Rules match the last six digits of the 10-digit logid. In the extremely unlikely event that two different FortiGate log types share the same six-digit message ID component, a false positive rule match could occur. If observed, add `<field name="type">` and `<field name="subtype">` filters to the affected rule.
