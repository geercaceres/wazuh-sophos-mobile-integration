# Sophos Mobile → Wazuh integration

Sophos Mobile SaaS **does not support syslog**. This integration pulls telemetry
from the Sophos Central REST APIs and writes JSON lines that Wazuh ingests with
`log_format json`.
![Uploading image.png…]()

| Source | `sophos_record` |
| --- | --- |
| `siem/v1/events` | `event` |
| `siem/v1/alerts` | `alert` |
| `mobile/v1/devices` | `device_status` |
| `mobile/v1/devices/{id}/compliance-violations` | `compliance_violation` |
| `mobile/v1/devices/{id}/installed-apps` | `installed_app`, `app_removed`, `forbidden_app` |

> **Status: deployed and verified against a live tenant** (Sophos Central trial,
> region `us03`) on Wazuh 4.14.7 with one enrolled Windows device. 42 rules, a
> 44-case `wazuh-logtest` suite passing, and a 12-panel dashboard.

## How it works

```
Sophos Central API ──OAuth2──> custom-sophos-mobile.py ──JSON lines──> /var/log/sophos-mobile/events.json
                                       │                                        │
                                  state file                             <localfile> json
                              (cursors + hashes)                                 │
                                                                  42 rules → alerts.json → indexer → dashboard
```

A `command` wodle runs the script every 5 minutes. Authentication is
`client_credentials` against `id.sophos.com`, followed by `whoami/v1` to resolve
the tenant ID and data region; every subsequent call carries
`Authorization: Bearer` plus `X-Tenant-ID`.

The SIEM API only retains 24 hours of data, which is why polling uses a
persistent cursor. Device and app records are deduplicated by hash, so a run
that finds nothing new emits nothing.

## API findings

The initial research assumed endpoints and field names that turned out to be
wrong. These were corrected against real API responses:

| Assumed | Verified |
| --- | --- |
| `/smc/v1/devices` | **404 `ApplicationNotFound`.** On Central-managed tenants the path is **`/mobile/v1/devices`** |
| `complianceStatus` matching `non*` / `violat*` | `compliance.compliant`, a boolean |
| `managementStatus` | `managedState`, value `"managed"` |
| `type` contains `compliance` | `Event::Endpoint::Mobile::NowCompliant`, `::Added`, `::Enrolled`, `::Action::Succeeded` |
| free-form `limit` | SIEM API requires **200 ≤ limit ≤ 1000** (outside that range → HTTP 400) |

Endpoints that exist and return 200: `mobile/v1/devices`,
`.../compliance-violations`, `.../installed-apps`, `mobile/v1/policies`.
Endpoints that return 404: `mobile/v1/apps`, `mobile/v1/tasks`,
`.../certificates`, and all of `smc/v1/*`.

### Real `mobile/v1/devices` payload

```json
{
  "id": "<device-uuid>", "name": "device-name",
  "compliance": {"compliant": true},
  "healthState": {"mode": "automatic", "state": "green"},
  "managedState": "managed", "managementType": "fullMdm",
  "os": {"platform": "windows", "name": "Windows 10.0.26200.8973"},
  "ownershipType": "corporate", "lastSeenAt": "2026-08-03T11:44:03.000Z",
  "email": "user@example.com", "tenant": {"id": "<tenant-uuid>"}
}
```

### Real `siem/v1/events` payload

```json
{
  "endpoint_type": "mobile", "endpoint_id": "<device-uuid>",
  "severity": "low", "group": "MOBILES",
  "type": "Event::Endpoint::Mobile::NowCompliant",
  "name": "The mobile device is now compliant",
  "location": "device-name", "source": "user name",
  "when": "...", "created_at": "...", "id": "...",
  "customer_id": "...", "user_id": "...", "source_info": {}
}
```

## Installation

**1. Create the API credential in Sophos Central**

Global Settings → API Credentials Management → Add Credential, role
**Service Principal ReadOnly**. The client secret is shown only once.

**2. Configure it locally.** `credentials.env` is gitignored and never
committed:

```bash
cp credentials.env.example credentials.env
$EDITOR credentials.env
```

**3. Deploy:**

```bash
bash deploy.sh wazuh-user@wazuh-manager.example.com
```

`deploy.sh` generates the config file, copies it with `scp` (never as a
command-line argument) and runs `setup-remote.sh` as root, which installs the
script, rules and credentials, patches `ossec.conf`, **validates with
`wazuh-analysisd -t` before restarting**, and prints an auth/fetch test.

### Dashboard

```bash
scp dashboard/sophos-mobile-dashboard.ndjson dashboard/load-dashboard.sh wazuh-user@HOST:/tmp/
ssh wazuh-user@HOST 'sudo bash /tmp/load-dashboard.sh /tmp/sophos-mobile-dashboard.ndjson'
```

To regenerate the saved objects, for example against a different index pattern:

```bash
python3 dashboard/make_dashboard.py out.ndjson [index-pattern-id] [field-suffix]
```

12 panels plus a saved search: metric tiles (total, compliance violations,
mobile threats, level ≥ 10), a time series by level, pies by record type and
platform, tables of top rules / devices / event names / app inventory, and the
latest alerts. It references the stock `wazuh-alerts-*` index pattern without
modifying it.

### Testing the rules

```bash
scp tests/rule-tests.sh wazuh-user@HOST:/tmp/
ssh wazuh-user@HOST 'sudo bash /tmp/rule-tests.sh'
```

44 cases through `wazuh-logtest`, including Android scenarios a Windows-only
tenant cannot produce (root, malware, PUA, ADB, forbidden apps) plus regressions
for every verified real payload.

## Configuration

What you put in `credentials.env` ends up in
`/var/ossec/etc/sophos-mobile.json` (root:wazuh, 0640):

```json
{
  "client_id": "...",
  "client_secret": "...",
  "poll_installed_apps": true,
  "forbidden_apps": ["(?i)tiktok", "(?i)telegram"]
}
```

`forbidden_apps` are Python regexes evaluated against each installed app's
identifier and name. Every match raises rule **100628 (level 12)**, once per
device per app; if the app is uninstalled and reinstalled it alerts again. This
covers the "prohibited apps" use case **without depending on the customer
configuring compliance policies in Sophos**.

## Verification

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-sophos-mobile.py --test
tail -f /var/ossec/logs/alerts/alerts.json | grep sophos_mobile
```

To exercise rules without waiting for real events — one record per line, and
**without `-q`**, which suppresses all output:

```bash
echo '{"integration":"sophos_mobile","sophos_record":"device_status","sophos":{"name":"dev1","compliance":{"compliant":false},"managedState":"managed"}}' | /var/ossec/bin/wazuh-logtest
```

## Event structure in Wazuh

```json
{
  "integration": "sophos_mobile",
  "sophos_record": "event | alert | device_status | compliance_violation | installed_app | app_removed | forbidden_app",
  "sophos": { "...Sophos payload plus fields the integration adds..." }
}
```

Wazuh's native JSON decoder handles this on its own — no custom decoder. Two
details matter when writing rules:

- Nested objects are flattened with dots (`sophos.compliance.compliant`).
- **Booleans arrive as strings**, which is why the compliance rule matches
  `"false"` and not `false`.

All fields are mapped as `keyword` in the indexer, so they aggregate without a
`.keyword` suffix.

## Rules (100600-100649)

**File order matters.** Wazuh evaluates sibling rules in order and keeps the
**first** match — not the most specific one, and not the highest level. That is
why the severity rules (100602/100603) are deliberately **last** among the
children of 100601. Put new rules before them.

### Base and catch-all

| ID | Level | Fires on |
| --- | --- | --- |
| **100600** | 3 | **Catch-all: any record from the integration.** Nothing from Sophos is silently dropped — whatever matches no child rule still alerts here |
| 100601 | 3 | `sophos_record=event`, unclassified |

To see everything in the dashboard: `rule.groups:sophos_mobile`.

### SIEM events

| ID | Level | Fires on |
| --- | --- | --- |
| 100648 | 12 | Root / jailbreak in the event text |
| 100641 | 12 | `type` = `Threat::(Detected\|CleanupFailed)` |
| 100642 | 12 | malware / malicious app / trojan in the text |
| 100643 | 10 | `type` = `Threat::Pua*` |
| 100649 | 10 | suspicious app / PUA(s) in the text |
| 100644 | 9 | `type` = `Application::(Blocked\|Detected)` |
| 100645 | 7 | `WebControlViolation`, `WebFilteringBlocked` |
| 100610 | 3 | `NowCompliant` / `Endpoint::Compliant` (back in compliance) |
| 100611 | 9 | `type` contains `(Not\|Non\|In)Compliant` |
| 100612 | 9 | Text fallback: `not` / `non compliant` |
| 100636 | 9 | ADB / developer mode / USB debugging |
| 100637 | 9 | Encryption |
| 100638 | 9 | Forbidden / mandatory / installed apps, unknown sources, third-party profiles |
| 100639 | 7 | Screen lock / passcode |
| 100613 | 3 | `type` = `Mobile::(Added\|Enrolled)` |
| 100614 | 7 | `type` = `Mobile::(Removed\|Deleted\|Unenrolled\|Deregistered)` |
| 100615 | 7 | `type` = `Mobile::Action::Failed` |
| 100646 | 7 | `Management::Suspended` |
| 100647 | 5 | `OutOfDate` / `UpdateFailure` |
| 100602 | 7 | *Fallback*: `severity=medium` |
| 100603 | 12 | *Fallback*: `severity=high\|critical` |

### SIEM alerts

| ID | Level | Fires on |
| --- | --- | --- |
| 100619 | 12 | Description mentioning root / jailbreak / malware |
| 100618 | 12 | `severity=high\|critical` |
| 100617 | 7 | Any other alert |

### Device inventory

| ID | Level | Fires on |
| --- | --- | --- |
| 100620 | 3 | `device_status` (inventory changed) |
| **100621** | 9 | **`compliance.compliant` = `false` → NON-COMPLIANT** |
| **100622** | 7 | **`managedState` ≠ `managed` (`negate="yes"`) → left MDM** |
| 100623 | 10 | `healthState.state` = `red` |
| 100624 | 7 | `healthState.state` = `suspicious` |

### Compliance violations and app inventory

| ID | Level | Fires on |
| --- | --- | --- |
| 100625 | 9 | `compliance_violation`, unclassified |
| 100630 | 12 | Root / jailbreak |
| 100631 | 12 | Malware |
| 100632 | 10 | Suspicious / PUA(s) |
| 100633 | 9 | ADB / developer mode |
| 100634 | 9 | Encryption |
| 100635 | 9 | Mandatory / forbidden / installed apps, unknown sources |
| 100640 | 7 | Screen lock, OS version, permissions, sync intervals, roaming, container, web filtering |
| 100626 | 3 | `installed_app` (new app) |
| 100627 | 3 | `app_removed` |
| **100628** | 12 | **`forbidden_app` (matched `forbidden_apps`)** |

Useful groups for filtering: `sophos_mobile`, `compliance_violation`,
`mobile_threat`, `mobile_app_inventory`.

## Android / iOS coverage: what is verified and what is not

**Verified with real data:** everything under `device_status`, the five event
types the tenant produced, `installed-apps` polling (195 apps on the enrolled
device), and the complete `forbidden_app` path through to alert 100628.

**Not verified, matched by text:** the `Event::Endpoint::Mobile::*` identifiers
are not publicly documented and this tenant only produced five of them. The
Android/iOS rules therefore **do not guess at `type` strings** — they match the
*compliance rule names* from Sophos' official documentation, which appear in the
event text and in the violation payload:

- Android: `Root access allowed`, `Android Debug Bridge (ADB) allowed`,
  `Malware apps allowed`, `Suspicious apps allowed`, `PUAs allowed`,
  `Encryption required`, `Screen lock required`, `Minimum/Maximum OS version`,
  `Mandatory apps`, `Installed apps`,
  `Intercept X for Mobile permissions can be denied`
- iOS: `Allow jailbreak`, `Third-party profiles allowed`,
  `Unmanaged apps from unknown sources allowed`, `Web Filtering turned on`

([Available compliance rules](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/CompliancePolicies/AvailableComplianceRules/))

The `compliance-violations` payload shape is still unknown (the tenant has no
active violations), so the integration also emits **`sophos.violationText`** —
the whole violation serialised to a single string — and the `1006[3x]` rules
match on that instead of on invented keys. Once a real payload is observed,
tighten them to the real keys.

## Operational notes

- **First batch:** when logcollector discovers a monitored file that *already*
  has content, it seeks to EOF and never reads what was there. The installer
  pre-creates `events.json` empty before the restart to avoid this. If you lose
  the initial alerts anyway: `rm -f /var/ossec/var/sophos-mobile.state` and run
  the script again.
- **App baseline:** the first time a device is seen, its app list is recorded
  *without alerting* — otherwise 195 alerts would land at once. From then on only
  installs and removals are reported. The `forbidden_apps` check does run on that
  first pass, since an already-installed prohibited app is exactly what needs
  reporting.
- **Cost per cycle:** each run makes 2 SIEM calls + 1 devices call + 2 per device
  (violations and apps). On large fleets, raise `<interval>` or set
  `poll_installed_apps: false`.
- **Log growth:** `events.json` is appended to indefinitely. Add a logrotate rule
  for anything long-lived.
- **Never pass secrets on a command line** on a Wazuh host: `journald` records
  `sudo` command lines and Wazuh's own rule 5402 turns them into alerts, which
  would put the secret into `alerts.json`.
- **Rotate the client secret** when a POC ends (Global Settings → API
  Credentials Management).

## Pending

- Confirm the real `compliance-violations` payload and Android event types once
  an Android device is enrolled, then tighten the `1006[3x]` rules to the real
  keys.
- `installed-apps` does not return an app version (at least on Windows). If it
  does on Android, rules for vulnerable versions become possible.
- If `mobile/v1/devices` returns 403/404 on another tenant, the Sophos Mobile API
  is not enabled there; the script logs it and continues with the SIEM API.

## Files

| File | What it is |
| --- | --- |
| `integration/custom-sophos-mobile.py` | The integration (runs as a command wodle every 5 min) |
| `rules/sophos_mobile_rules.xml` | 42 rules, IDs 100600-100649 |
| `wazuh/ossec_conf_snippet.xml` | Reference `<wodle>` + `<localfile>` blocks |
| `deploy.sh` | Generates the config, copies everything, runs the installer over SSH |
| `setup-remote.sh` | Installer, runs as root on the manager |
| `credentials.env.example` | Credential template (copy to `credentials.env`) |
| `dashboard/make_dashboard.py` | Generates the dashboard saved objects |
| `dashboard/load-dashboard.sh` | Imports the dashboard through the API |
| `dashboard/sophos-mobile-dashboard.ndjson` | Generated saved objects |
| `tests/rule-tests.sh` | 44 rule tests with `wazuh-logtest` |

**No credentials in the repo.** `credentials.env` is gitignored; only the
template is versioned.

## License

Copyright (C) 2026 Gerardo Cáceres

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU General Public License version 2** as published by the
Free Software Foundation. See [LICENSE](LICENSE) for the full text.

It is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of merchantability or fitness for
a particular purpose.

GPLv2 is the same license Wazuh uses, so this code stays compatible with the
project's ruleset and integrations.

## References

- [Sophos Central SIEM Integration (official)](https://github.com/sophos/Sophos-Central-SIEM-Integration)
- [Sophos SIEM API](https://developer.sophos.com/docs/siem-v1/1/overview)
- [API event and alert types](https://support.sophos.com/support/s/article/KBA-000006285)
- [Available compliance rules (Sophos Mobile)](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/CompliancePolicies/AvailableComplianceRules/)
- [Mobile Threat Defense compliance rules](https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/MTDWithIXM/ComplianceRules/index.html)
