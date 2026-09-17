# -*- coding: utf-8 -*-
# doc_content.py - part of the Sophos Mobile to Wazuh integration
# Copyright (C) 2026 Gerardo Caceres
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <https://www.gnu.org/licenses/>.
#
# Prose for the customer-facing document. Flags per run: b bold, i italic,
# c code. The appendices read the real files from the repository, so they
# cannot drift from the code.
import io
import os

B, C = "b", "c"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OPS = []
a = OPS.append


def src(rel):
    with io.open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return [ln.rstrip("\n").rstrip("\r") for ln in f]


def count_rules():
    import xml.etree.ElementTree as ET
    root = ET.parse(os.path.join(REPO, "rules/sophos_mobile_rules.xml")).getroot()
    return len(root.findall("rule"))


def count_tests():
    return sum(1 for ln in src("tests/rule-tests.sh") if ln.startswith("run "))


NRULES = str(count_rules())
NTESTS = str(count_tests())

# ------------------------------------------------------------------- cover
a(("title", "Sophos Mobile integration with Wazuh"))
a(("sub", "Technical documentation and proof-of-concept guide"))
a(("table", ["Field", "Detail"], [
    [[("Scope", B)], "Ingesting Sophos Mobile / Sophos Central telemetry into Wazuh over the REST API"],
    [[("Integration type", B)], "Pull-based. A command wodle on the Wazuh manager writes JSON that logcollector ingests"],
    [[("Sophos products", B)], "Sophos Mobile (SaaS, managed through Sophos Central); Sophos Central SIEM API"],
    [[("Wazuh versions", B)], "Wazuh 4.x, manager side only. Validated end to end on 4.14.7"],
    [[("Detection content", B)], NRULES + " rules, IDs 100600-100699, plus a " + NTESTS + "-case automated test suite"],
    [[("Visualization", B)], "A dashboard of 12 panels, one of which is a saved search"],
    [[("Document status", B)], "Validated end to end. Section 6.1 states precisely what is verified and what is inferred"],
], [2100, 7260]))
a(("spacer", 14))
a(("callout", "Read this first.",
   "Sophos Mobile does not support syslog forwarding. The product exposes no log shipping, no local log "
   "files and no agent that Wazuh could read, so the only way to bring its telemetry into Wazuh is the "
   "Sophos Central REST API. This is a custom integration, not a Wazuh out-of-the-box module."))
a(("break",))

# --------------------------------------------------------------------- TOC
a(("h1", "Contents"))
a(("toc",))
a(("break",))

# ----------------------------------------------------------------------- 1
a(("h1", "1. Overview"))
a(("h2", "1.1 Purpose and scope"))
a(("p", "This document describes how to deploy, validate and operate an integration that brings Sophos "
        "Mobile telemetry into Wazuh. It is written for the engineer running the proof of concept and "
        "covers prerequisites, installation, the detection rules included, how to prove the pipeline works "
        "end to end, and the operational limits to be aware of."))
a(("p", "Deploying Wazuh itself, enrolling devices into Sophos Mobile and changing Sophos policies are out "
        "of scope. The integration is read-only: it never writes to Sophos and never issues management "
        "actions against devices."))

a(("h2", "1.2 Why an API integration"))
a(("p", "Sophos Mobile is a SaaS product administered from Sophos Central. Telemetry is pulled from two "
        "API families:"))
a(("bullet", [("Sophos Central SIEM API", B), " provides tenant-wide security events and alerts, "
              "including those raised by mobile devices."]))
a(("bullet", [("Sophos Mobile API", B), " provides device inventory, compliance state, per-device "
              "compliance violations and installed applications."]))
a(("p", ["A Python script on the Wazuh manager authenticates, polls both APIs and writes each record as a "
         "JSON line. Wazuh decodes it with its native JSON decoder, so ",
         ("no custom decoder is required", B), "."]))

a(("h2", "1.3 Wazuh version support"))
a(("p", ["The integration runs on ", ("any Wazuh 4.x manager", B), " and was validated end to end on "
         "4.14.7. It deliberately uses nothing version specific: a command wodle, a localfile with "
         "JSON log format, the built-in JSON decoder, and custom rules in the 100000 and above range. "
         "All of these have been stable across the 4.x line."]))
a(("p", "Older 4.x minor versions have not been tested, and neither has Wazuh 5.x. The integration "
        "installs only on the manager; no agent is involved at any point, and no agent needs upgrading."))

a(("h2", "1.4 What the integration delivers"))
a(("table", ["Capability", "How it is delivered"], [
    ["Mobile security events and alerts", "Cursor-based polling of the SIEM API every 5 minutes"],
    ["Device compliance state", "Device inventory polling; alerts when a device becomes non-compliant, leaves management, or its health degrades"],
    ["Compliance violations", "Each new violation reported once and classified: root/jailbreak, malware, PUA, ADB, encryption, app policy, configuration"],
    ["Application inventory", "New installs and removals per device, plus detection of prohibited applications from an operator-supplied list"],
    ["MDM platform health", "APNs certificate expiry or revocation, Android enterprise binding loss, and Sophos Mobile license expiry"],
    ["Detection content", NRULES + " Wazuh rules with severity levels, MITRE references where applicable, and groups for filtering"],
    ["Visualization", "Metric tiles, a time series by severity, breakdowns by record type and platform, and top-N tables"],
], [2900, 6460]))

# ----------------------------------------------------------------------- 2
a(("h1", "2. Architecture"))
a(("h2", "2.1 Data flow"))
a(("code", [
    "  Sophos Central API",
    "        |   OAuth2 client_credentials (bearer token, 1 h)",
    "        v",
    "  custom-sophos-mobile.py         <- command wodle, every 5 minutes",
    "        |                            state file: cursors + hashes",
    "        v",
    "  /var/log/sophos-mobile/events.json    (one JSON object per line)",
    "        |   <localfile> log_format json",
    "        v",
    "  wazuh-logcollector -> wazuh-analysisd -> rules 100600-100699",
    "        |",
    "        v",
    "  alerts.json -> Wazuh indexer -> dashboard",
]))
a(("p", "All traffic is outbound HTTPS initiated by the manager. No inbound connectivity to Wazuh is "
        "required."))

a(("h2", "2.2 Components installed on the manager"))
a(("table", ["Path", "Purpose", "Ownership"], [
    [[("/var/ossec/integrations/custom-sophos-mobile.py", C)], "Integration script", [("root:wazuh 0750", C)]],
    [[("/var/ossec/etc/rules/sophos_mobile_rules.xml", C)], "Detection rules", [("wazuh:wazuh 0660", C)]],
    [[("/var/ossec/etc/sophos-mobile.json", C)], "API credentials and options", [("root:wazuh 0640", C)]],
    [[("/var/ossec/var/sophos-mobile.state", C)], "API cursors, device and app hashes", [("root:wazuh", C)]],
    [[("/var/log/sophos-mobile/events.json", C)], "Output read by logcollector", [("wazuh:wazuh", C)]],
], [3500, 3460, 2400]))
a(("p", ["Two blocks are appended to ", ("ossec.conf", C), ": a ", ("command", C), " wodle that runs the "
         "script on a 5-minute interval, and a ", ("localfile", C), " block that reads the JSON output. "
         "The original file is backed up first."]))

a(("h2", "2.3 Endpoints and record types"))
a(("p", ["Every record carries ", ("integration", C), " = ", ("sophos_mobile", C), " and a ",
         ("sophos_record", C), " field identifying its kind:"]))
a(("table", ["Sophos endpoint", "sophos_record", "Deduplication"], [
    [[("siem/v1/events", C)], [("event", C)], "Persistent API cursor"],
    [[("siem/v1/alerts", C)], [("alert", C)], "Persistent API cursor"],
    [[("mobile/v1/devices", C)], [("device_status", C)], "SHA-256 of the device object"],
    [[("mobile/v1/devices/{id}/compliance-violations", C)], [("compliance_violation", C)], "Hash per violation"],
    [[("mobile/v1/devices/{id}/installed-apps", C)],
     [("installed_app", C), ", ", ("app_removed", C), ", ", ("forbidden_app", C)],
     "Diff against a per-device baseline"],
], [3560, 2840, 2960]))
a(("callout", "Endpoint note.",
   ["On tenants managed through Sophos Central the Mobile API is served under ", ("mobile/v1/", C),
    ". The ", ("smc/v1/", C), " paths documented for standalone Sophos Mobile return HTTP 404 on these "
    "tenants and must not be used."]))

a(("h2", "2.4 Polling, deduplication and state"))
a(("p", "The SIEM API retains only 24 hours of data, so polling uses the cursor the API returns on each "
        "call. The cursor is persisted, advances on every request and does not re-deliver records already "
        "seen. On a first run with no stored cursor the script requests the last 12 hours."))
a(("p", "Device and application data have no cursor, so change detection happens locally: a device is "
        "re-emitted only when the hash of its object changes, and applications are compared against a "
        "stored baseline. A cycle that finds nothing new writes nothing and raises no alerts."))

# ----------------------------------------------------------------------- 3
a(("h1", "3. Prerequisites"))
a(("h2", "3.1 Sophos Central"))
a(("table", ["Requirement", "Detail"], [
    ["Licensing", "An active Sophos Mobile subscription or trial, with at least one enrolled device"],
    ["Administrator access", "Rights to create API credentials in Sophos Central"],
    ["Credential type", "Service principal with the ReadOnly role (section 4.1)"],
    ["Tenant scope", "A tenant-level credential. Partner and organization credentials require additional headers and are not supported"],
], [2400, 6960]))
a(("h2", "3.2 Wazuh"))
a(("table", ["Requirement", "Detail"], [
    ["Version", "Any Wazuh 4.x manager. Validated on 4.14.7. See section 1.3"],
    ["Component", "Wazuh server (manager). The integration runs on the manager, not on an agent"],
    ["Python", ["The interpreter bundled with Wazuh at ", ("/var/ossec/framework/python/bin/python3", C),
                ", which already provides ", ("requests", C), ". Nothing needs installing"]],
    ["Privileges", "root on the manager, for the installation only"],
    ["Dashboard", "Wazuh dashboard reachable over HTTPS with an account allowed to import saved objects"],
], [2400, 6960]))
a(("h2", "3.3 Network"))
a(("table", ["Source", "Destination", "Port", "Purpose"], [
    ["Wazuh manager", [("id.sophos.com", C)], "443/TCP", "OAuth2 token request"],
    ["Wazuh manager", [("api.central.sophos.com", C)], "443/TCP",
     ["Tenant and region discovery (", ("whoami", C), ")"]],
    ["Wazuh manager", [("api-<region>.central.sophos.com", C)], "443/TCP", "SIEM and Mobile API calls"],
], [1900, 3600, 1100, 2760]))
a(("p", ["The regional hostname is discovered at runtime and differs per tenant, so firewall allow-lists "
         "should permit ", ("*.central.sophos.com", C), " rather than a single host."]))

# ----------------------------------------------------------------------- 4
a(("h1", "4. Installation"))
a(("h2", "4.1 Create the API credential"))
a(("step", "Sign in to Sophos Central as an administrator."))
a(("step", ["Open ", ("Global Settings > API Credentials Management", B), " and select ",
            ("Add Credential", B), "."]))
a(("step", ["Name it, for example ", ("wazuh-integration", C), ", and assign the role ",
            ("Service Principal ReadOnly", B), "."]))
a(("step", "Record the Client ID and Client Secret. The secret is shown only once."))
a(("callout", "Least privilege.",
   "The read-only service principal role is sufficient for everything in this document. Do not grant a "
   "role with write permissions: the integration never modifies Sophos configuration or devices."))

a(("h2", "4.2 Configure the credentials"))
a(("p", "On the machine you deploy from, copy the template and fill it in. This file is excluded from "
        "version control and is the only place the secret is written:"))
a(("code", [
    "cp credentials.env.example credentials.env",
    "",
    "# credentials.env",
    "SOPHOS_CLIENT_ID=00000000-0000-0000-0000-000000000000",
    "SOPHOS_CLIENT_SECRET=<the secret shown by Sophos Central>",
    "SOPHOS_POLL_INSTALLED_APPS=true",
    'SOPHOS_FORBIDDEN_APPS=["(?i)tiktok", "(?i)telegram"]',
]))

a(("h2", "4.3 Deploy"))
a(("code", ["bash deploy.sh <user>@<wazuh-manager>"]))
a(("p", ["The script builds the configuration file locally, copies it to the manager with ", ("scp", C),
         " and runs the installer under ", ("sudo", C), "."]))
a(("callout", "Never pass the secret on a command line.",
   ["On a Wazuh manager, journald records sudo command lines and Wazuh rule 5402 turns them into alerts. "
    "A secret supplied as a command-line argument would end up in ", ("alerts.json", C),
    " and in the indexer. The deployment copies the credential as a file for exactly this reason."]))

a(("h2", "4.4 What the installer does"))
a(("step", "Installs the script, rules and credential file with the ownership in section 2.2, then "
           "securely deletes the temporary copy of the credential."))
a(("step", ["Creates ", ("/var/log/sophos-mobile/", C), " and pre-creates ", ("events.json", C), " empty."]))
a(("step", ["Appends the wodle and localfile blocks to ", ("ossec.conf", C), ", after backing it up as ",
            ("ossec.conf.bak-sophos", C), "."]))
a(("step", ["Runs ", ("wazuh-analysisd -t", C), " and aborts without restarting if the configuration or "
            "ruleset fails to parse."]))
a(("step", "Runs an authentication and fetch test, printing the records retrieved."))
a(("step", ["Restarts ", ("wazuh-manager", C), "."]))
a(("callout", "Why the log file is pre-created empty.",
   "When logcollector discovers a monitored file that already contains data, it seeks to the end and never "
   "reads what was there. If the integration ran before logcollector began tracking the file, its first "
   "batch would be silently discarded. Creating the file empty before the restart makes logcollector "
   "track it from offset zero."))

a(("h2", "4.5 Load the dashboard"))
a(("code", [
    "scp dashboard/sophos-mobile-dashboard.ndjson \\",
    "    dashboard/load-dashboard.sh <user>@<wazuh-manager>:/tmp/",
    "",
    "ssh <user>@<wazuh-manager> \\",
    "  'sudo bash /tmp/load-dashboard.sh /tmp/sophos-mobile-dashboard.ndjson'",
]))
a(("p", ["The importer verifies that the ", ("wazuh-alerts-*", C), " index pattern exists and imports 13 "
         "saved objects. It references that index pattern without modifying it, so no existing Wazuh "
         "content is altered."]))

# ----------------------------------------------------------------------- 5
a(("break",))
a(("h1", "5. Detection rules"))
a(("p", [NRULES, " rules occupy IDs 100600-100699, inside the range Wazuh reserves for custom rules. "
         "They are delivered as a single file and are designed so that no Sophos record is ever lost."]))

a(("h2", "5.1 Design principles"))
a(("h3", "Nothing is silently dropped"))
a(("p", ["Rule ", ("100600", C), " matches only ", ("integration = sophos_mobile", C), " with no further "
         "condition. Any record that matches none of the more specific child rules still produces an alert "
         "through it. To see every Sophos record in the dashboard, filter on:"]))
a(("code", ["rule.groups:sophos_mobile"]))

a(("h3", "Level decides, file order only breaks ties"))
a(("p", "Wazuh sorts the children of a rule by level descending and keeps the first one that matches. "
        "File order applies only among rules of the same level. This is the single most important thing "
        "to know before adding a rule to this set, and it is easy to get backwards."))
a(("p", ["Verified with ", ("wazuh-logtest -v", C), " on 4.14.7. The children of 100601 are tried in this "
         "order, which is by level and not by position in the file:"]))
a(("code", [
    "100648(12)  100641(12)  100642(12)  100652(12)  100603(12)",
    "100643(10)  100649(10)  100650(10)",
    "100644(9)   100611(9)   ...",
]))
a(("callout", "Practical consequence.",
   ["A specific rule needs a level greater than or equal to the generic sibling it is meant to beat, or "
    "the generic one wins wherever it sits in the file. Two rules in this set are levelled for exactly "
    "that reason: 100651 is level 9 rather than 7 because at 7 it lost to the generic 100611, and 100655 "
    "is level 12 so it wins over the high-severity fallback 100603."]))

a(("h3", "Booleans and nested fields"))
a(("p", ["Wazuh's JSON decoder flattens nested objects with dotted names and converts booleans to strings. "
         "The device compliance field therefore appears as ", ("sophos.compliance.compliant", C),
         " with the value ", ('"false"', C), ", and the rule matches the string, not a boolean. All Sophos "
         "fields are mapped as ", ("keyword", C), " in the indexer, so they aggregate in the dashboard "
         "without a ", (".keyword", C), " suffix."]))

a(("h2", "5.2 Rule reference"))
a(("h3", "Base rules"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100600", C)], "3", "Catch-all. Any record produced by the integration"],
    [[("100601", C)], "3", "A SIEM event that matched no more specific rule"],
], [1100, 900, 7360]))

a(("h3", "Threats on mobile devices"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100648", C)], "12", "Root or jailbreak condition named in the event text"],
    [[("100641", C)], "12", ["Event type ", ("Threat::Detected", C), " or ", ("Threat::CleanupFailed", C)]],
    [[("100642", C)], "12", "Malware, malicious application or trojan named in the event text"],
    [[("100643", C)], "10", ["Event type ", ("Threat::Pua*", C)]],
    [[("100649", C)], "10", "Suspicious application or PUA named in the event text"],
    [[("100644", C)], "9", ["Event type ", ("Application::Blocked", C), " or ", ("Application::Detected", C)]],
    [[("100645", C)], "7", "Web control violation or web filtering block"],
], [1100, 900, 7360]))

a(("h3", "Compliance"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100610", C)], "3", "Device returned to compliance"],
    [[("100650", C)], "10", [("NowNonCompliant::GENERAL_BLACKLISTED_APPS", C), " or ", ("WHITELISTED", C), ", a forbidden app is installed"]],
    [[("100651", C)], "9", [("NowNonCompliant::GENERAL_MANDATORY_APPS", C), ", a mandatory app is missing"]],
    [[("100611", C)], "9", "Event type indicating the device is not compliant"],
    [[("100612", C)], "9", "Text fallback for non-compliance wording"],
    [[("100636", C)], "9", "ADB, developer mode or USB debugging"],
    [[("100637", C)], "9", "Encryption requirement not met"],
    [[("100638", C)], "9", "Application policy: forbidden, mandatory or unmanaged applications, unknown sources, third-party profiles"],
    [[("100639", C)], "7", "Screen lock or passcode requirement not met"],
], [1100, 900, 7360]))

a(("h3", "Device lifecycle and management"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100613", C)], "3", "Device added or enrolled"],
    [[("100658", C)], "3", ["Event type ", ("Mobile::EnrolledNewApp", C)]],
    [[("100614", C)], "7", "Device removed, deleted, unenrolled or deregistered, including by the user"],
    [[("100615", C)], "7", "A management action failed on the device"],
    [[("100657", C)], "5", ["Event type ", ("Mobile::Action::Cancelled", C), " or ", ("Skipped", C)]],
    [[("100646", C)], "7", "Protection suspended"],
    [[("100647", C)], "5", "Device out of date, or an update failed"],
    [[("100659", C)], "3", "Enrollment data missing: Exchange information, a placeholder, or a user email address"],
    [[("100602", C)], "7", ["Fallback: ", ("severity = medium", C)]],
    [[("100603", C)], "12", ["Fallback: ", ("severity = high", C), " or ", ("critical", C)]],
], [1100, 900, 7360]))

a(("h3", "MDM platform health"))
a(("p", "These do not concern a single device. They break management for a whole platform, which is why "
        "two of them are level 12 even though Sophos files them as routine events."))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100652", C)], "12", "APNs certificate expired or revoked. Every iOS device silently stops accepting MDM commands"],
    [[("100653", C)], "7", "APNs certificate missing, or about to expire"],
    [[("100654", C)], "3", "APNs certificate renewed"],
    [[("100655", C)], "12", "Android enterprise binding lost. No Android device can be managed until Sophos Mobile is registered again as the EMM provider"],
    [[("100656", C)], "7", "The Sophos Mobile license is about to expire"],
], [1100, 900, 7360]))

a(("h3", "Alerts from the SIEM API"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100619", C)], "12", "Alert description mentioning root, jailbreak or malware"],
    [[("100618", C)], "12", "Alert of high or critical severity"],
    [[("100617", C)], "7", "Any other alert"],
], [1100, 900, 7360]))

a(("h3", "Device inventory"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100620", C)], "3", "Device inventory changed"],
    [[("100621", C)], "9", ["Device is ", ("NON-COMPLIANT", B), " (", ("compliance.compliant = false", C), ")"]],
    [[("100622", C)], "7", ["Device is no longer managed (", ("managedState", C),
                            " is anything other than ", ("managed", C), ")"]],
    [[("100623", C)], "10", "Device health is red"],
    [[("100624", C)], "7", "Device health is suspicious"],
], [1100, 900, 7360]))

a(("h3", "Compliance violations and applications"))
a(("table", ["ID", "Level", "Fires on"], [
    [[("100625", C)], "9", "A compliance violation that matched no more specific rule"],
    [[("100630", C)], "12", "Violation: device rooted or jailbroken"],
    [[("100631", C)], "12", "Violation: malware application"],
    [[("100632", C)], "10", "Violation: suspicious application or PUA"],
    [[("100633", C)], "9", "Violation: ADB or developer mode enabled"],
    [[("100634", C)], "9", "Violation: encryption"],
    [[("100635", C)], "9", "Violation: application policy"],
    [[("100640", C)], "7", "Violation: configuration (screen lock, OS version, permissions, sync intervals, roaming, container, web filtering)"],
    [[("100626", C)], "3", "New application installed on a device"],
    [[("100627", C)], "3", "Application removed from a device"],
    [[("100628", C)], "12", ["A ", ("prohibited application", B), " is present (matched the operator-supplied list)"]],
], [1100, 900, 7360]))
a(("p", ["Rules are also tagged with groups so they can be filtered without knowing IDs: ",
         ("sophos_mobile", C), ", ", ("compliance_violation", C), ", ", ("mobile_threat", C), ", ",
         ("mobile_app_inventory", C), " and ", ("mobile_management", C), "."]))

a(("h2", "5.3 Alert structure"))
a(("p", "Each line written by the integration has the same envelope, so the original Sophos payload is "
        "preserved intact for searching and correlation:"))
a(("code", [
    "{",
    '  "integration": "sophos_mobile",',
    '  "sophos_record": "device_status",',
    '  "sophos": {',
    '    "id": "...", "name": "<device name>",',
    '    "compliance": {"compliant": true},',
    '    "healthState": {"state": "green", "mode": "automatic"},',
    '    "managedState": "managed", "managementType": "fullMdm",',
    '    "os": {"platform": "android", "name": "..."},',
    '    "ownershipType": "corporate", "lastSeenAt": "..."',
    "  }",
    "}",
]))
a(("p", ["In the resulting Wazuh alert these become ", ("data.sophos.*", C), " fields, for example ",
         ("data.sophos.os.platform", C), " and ", ("data.sophos.compliance.compliant", C), "."]))

# ----------------------------------------------------------------------- 6
a(("break",))
a(("h1", "6. Android and iOS coverage"))
a(("h2", "6.1 Verified, confirmed and inferred"))
a(("p", "This section is deliberately explicit, because it determines how much confidence to place in "
        "each rule during the proof of concept."))
a(("table", ["Area", "Status"], [
    ["Authentication, tenant discovery, all endpoints", [("Verified", B), " against a live tenant"]],
    ["Device inventory fields and their values", [("Verified", B), " against a live tenant. Every field in section 5.3 came from a real API response"]],
    ["Event envelope and field names", [("Verified", B), " against a live tenant"]],
    ["Application inventory and prohibited-app detection", [("Verified", B), " end to end, including the resulting alert"]],
    ["Mobile event type identifiers", [("Confirmed from a public ruleset", B), ". Sophos does not document them, but Quadrant's sagan-rules project carries the full list, each cross-referenced to a Sophos KB article"]],
    ["Root, jailbreak, encryption, passcode, OS version", [("Inferred", B), ". Not covered by the identifier list, so matched against the compliance rule names from Sophos' documentation"]],
    ["Compliance violation payload structure", [("Inferred", B), ". The reference tenant had no active violations, so the field names inside a violation could not be confirmed"]],
], [3200, 6160]))

a(("h2", "6.2 Confirmed event type identifiers"))
a(("p", "These drive the type-based rules. The suffix on a non-compliance event is the reason for the "
        "violation, which is what makes the app-policy rules precise rather than text matching."))
a(("code", [
    "Event::Endpoint::Mobile::NowCompliant",
    "Event::Endpoint::Mobile::NowNonCompliant",
    "  ::0  ::UNKNOWN  ::GENERAL_BLACKLISTED_APPS  ::GENERAL_WHITELISTED_APPS",
    "  ::GENERAL_MANDATORY_APPS            <- the suffix is the reason",
    "Event::Endpoint::Mobile::Added  ::Enrolled  ::EnrolledNewApp",
    "Event::Endpoint::Mobile::Unenrolled  ::UnenrolledByUser",
    "Event::Endpoint::Mobile::Action::Succeeded ::Failed ::Cancelled ::Skipped",
    "Event::Endpoint::Mobile::EasDataMissing  ::PlaceholderMissing",
    "Event::Mobile::ApnsCertificateExpired  ::ApnsCertificateRenewed",
    "Event::Mobile::ApnsCertificateRevoked  ::UserEmailMissing",
    "Event::Task::NoApnsCertificate",
    "Event::Task::RenewApnsCertificate::1|2|3",
    "Event::Smc::RenewSmcLicense::1|2|3     Event::Smc::AfwNotEnrolled",
]))

a(("h2", "6.3 Compliance rules matched by text"))
a(("p", "The identifier list above covers neither root nor jailbreak nor the configuration requirements, "
        "so those rules match the compliance rule names from Sophos' official documentation, which appear "
        "in the human-readable event text and in the violation payload."))
a(("table", ["Platform", "Sophos compliance rule", "Wazuh rule"], [
    ["Android", "Root access allowed", [("100648", C), " / ", ("100630", C)]],
    ["iOS", "Allow jailbreak", [("100648", C), " / ", ("100630", C)]],
    ["Android", "Malware apps allowed", [("100642", C), " / ", ("100631", C)]],
    ["Android", "Suspicious apps allowed, PUAs allowed", [("100649", C), " / ", ("100632", C)]],
    ["Android", "Android Debug Bridge (ADB) allowed", [("100636", C), " / ", ("100633", C)]],
    ["Android, iOS", "Encryption required", [("100637", C), " / ", ("100634", C)]],
    ["Android, iOS", "Installed apps, Mandatory apps", [("100650", C), " / ", ("100651", C), " / ", ("100635", C)]],
    ["iOS", "Unmanaged apps from unknown sources, Third-party profiles allowed", [("100638", C), " / ", ("100635", C)]],
    ["Android, iOS", "Screen lock required", [("100639", C), " / ", ("100640", C)]],
    ["Android, iOS", "Minimum / Maximum OS version, Mandatory OS updates", [("100640", C)]],
    ["Android", "Intercept X for Mobile permissions can be denied; sync and scan intervals", [("100640", C)]],
    ["Any", "Managed required", [("100622", C), " / ", ("100614", C)]],
], [1500, 5460, 2400]))
a(("callout", "How the inferred cases are handled.",
   ["The payload of a compliance violation has never been observed, so the integration serialises the "
    "whole violation into a single ", ("sophos.violationText", C), " field and the rules match on that "
    "rather than on invented key names. Detection therefore works regardless of the exact keys Sophos "
    "uses. Once a real violation is observed, the rules can be tightened to the actual keys."]))

a(("h2", "6.4 Prohibited application detection"))
a(("p", "This works today, on any platform, and does not depend on the customer configuring compliance "
        "policies in Sophos. A list of regular expressions is placed in the integration configuration and "
        "every installed application is checked against it:"))
a(("code", ['"forbidden_apps": ["(?i)tiktok", "(?i)telegram", "^com\\\\.example\\\\."]']))
a(("p", ["Each match raises rule ", ("100628", C), " at level 12, once per device and application. If the "
         "application is removed and installed again it alerts again. Matching is performed against both "
         "the application identifier and its display name."]))
a(("callout", "First run behaviour.",
   "The first time a device is seen, its full application list is stored as a baseline without raising "
   "alerts, otherwise a newly enrolled device would produce one alert per installed application (195 on "
   "the reference device). Only later installs and removals are reported. The prohibited-application "
   "check does run on that first pass, since an already-installed prohibited application is precisely "
   "what needs reporting."))

# ----------------------------------------------------------------------- 7
a(("h1", "7. Dashboard"))
a(("p", "The dashboard is delivered as saved objects and imported through the API. It references the "
        "standard Wazuh alerts index pattern and creates no new one. Twelve panels in total, one of which "
        "is a saved search."))
a(("table", ["Panel", "Shows"], [
    ["Total alerts", "All records received from the integration"],
    ["Compliance violations", "Count of alerts in the compliance_violation group"],
    ["Mobile threats", "Count of alerts in the mobile_threat group (root, jailbreak, malware, PUA)"],
    ["Alerts level 10 and above", "High-severity volume, for triage"],
    ["Alerts over time", "Time series broken down by rule severity"],
    ["Alerts by record type", "Proportion of events, alerts, device status, violations and app records"],
    ["Devices by platform", "Android, iOS and Windows distribution"],
    ["Top firing rules", "Rule ID and description, ranked"],
    ["Most active devices", "Devices generating the most records"],
    ["Most frequent Sophos events", "The event names seen most often"],
    ["App inventory", "Applications by name, split by install / removal / prohibited"],
    ["Latest alerts", "A saved search with severity, rule and record type columns"],
], [2800, 6560]))
a(("p", ["Any Wazuh view can be filtered with ", ("rule.groups:sophos_mobile", C), " to isolate this "
         "integration, which is also the quickest way to confirm that data is arriving."]))

# ----------------------------------------------------------------------- 8
a(("h1", "8. Validation and testing"))
a(("h2", "8.1 Authentication and fetch test"))
a(("p", "The script has a test mode that authenticates, retrieves data and prints it without saving state "
        "or writing to the log:"))
a(("code", [
    "/var/ossec/framework/python/bin/python3 \\",
    "  /var/ossec/integrations/custom-sophos-mobile.py --test",
]))
a(("p", "A healthy run reports the tenant and region it authenticated against, followed by a count for "
        "each source:"))
a(("code", [
    "sophos-mobile: authenticated OK, tenant=<id>, region=https://api-<region>.central.sophos.com",
    "sophos-mobile: events: 5 new items",
    "sophos-mobile: alerts: 0 new items",
    "sophos-mobile: devices: 1 total, 1 new/changed",
    "sophos-mobile: compliance violations: 0 new",
    "sophos-mobile: apps: baseline of 195 apps recorded (not alerted)",
]))

a(("h2", "8.2 Rule test suite"))
a(("p", ["A test script drives ", NTESTS, " crafted records through ", ("wazuh-logtest", C),
         " and asserts which rule fires for each. It covers scenarios a Windows-only tenant cannot "
         "generate, including root, jailbreak, malware, PUA, ADB, prohibited applications, APNs "
         "certificate expiry and the loss of the Android enterprise binding, as well as regressions for "
         "every payload observed in the live tenant:"]))
a(("code", ["sudo bash rule-tests.sh"]))
a(("p", "Expected output ends with:"))
a(("code", ["================ " + NTESTS + " passed, 0 failed ================"]))
a(("callout", "Testing rules by hand.",
   [("wazuh-logtest", C), " accepts one record per line on standard input. Do not pass ", ("-q", C),
    ": it suppresses the output entirely, which looks like a rule failure when it is not. Use ",
    ("-v", C), " to see the evaluation order, which is how the level-before-file-order behaviour in "
    "section 5.1 was established."]))

a(("h2", "8.3 End-to-end verification"))
a(("step", ["Confirm the wodle is running: look for ", ("Starting command 'sophos-mobile'", C), " in ",
            ("/var/ossec/logs/ossec.log", C), "."]))
a(("step", ["Confirm records are written: ", ("wc -l /var/log/sophos-mobile/events.json", C), "."]))
a(("step", ["Watch for alerts: ", ("tail -f /var/ossec/logs/alerts/alerts.json | grep sophos_mobile", C), "."]))
a(("step", ["In the dashboard, filter on ", ("rule.groups:sophos_mobile", C), "."]))
a(("p", ["To generate activity on demand, lock or unlock a device from the Sophos console, or breach a "
         "compliance policy, for example by requiring a higher OS version than the device runs. Note that ",
         ("alerts.json", C), " is rotated daily; the indexer retains the full history, which is what the "
         "dashboard reads."]))
a(("callout", "If the first batch produced no alerts.",
   ["This is the logcollector behaviour described in section 4.4. Reset the cursor and run the "
    "integration again so records are appended while logcollector is already tracking the file: ",
    ("rm -f /var/ossec/var/sophos-mobile.state", C), "."]))

# ----------------------------------------------------------------------- 9
a(("break",))
a(("h1", "9. Operational considerations"))
a(("h2", "9.1 API call volume"))
a(("p", "Each cycle makes two SIEM calls, one device call, and two calls per device (compliance "
        "violations and installed applications). With the default 5-minute interval:"))
a(("table", ["Devices", "Calls per cycle", "Calls per day", "Recommendation"], [
    ["1 - 25", "3 + 2 per device", "up to ~15,000", "Defaults are fine"],
    ["25 - 200", "3 + 2 per device", "~15,000 - 116,000", ["Raise the interval to ", ("15m", C)]],
    ["200 and above", "3 + 2 per device", "over 116,000",
     ["Raise the interval and set ", ("poll_installed_apps", C), " to ", ("false", C)]],
], [1500, 2200, 2300, 3360]))
a(("p", ["The interval is the ", ("<interval>", C), " value in the wodle block in ", ("ossec.conf", C),
         ". Keep it below 24 hours in all cases, because the SIEM API discards anything older than that."]))

a(("h2", "9.2 Log growth"))
a(("p", [("/var/log/sophos-mobile/events.json", C), " is appended to indefinitely. Because only changes "
         "are written the file grows slowly, but a long-lived deployment should have a logrotate rule for "
         "it. Rotating it is safe: logcollector detects the rotation and continues from the new file."]))

a(("h2", "9.3 Credential handling"))
a(("bullet", ["The secret is stored only in ", ("/var/ossec/etc/sophos-mobile.json", C), ", owned ",
              ("root:wazuh", C), " with mode ", ("0640", C), "."]))
a(("bullet", "It is never passed as a command-line argument, for the reason given in section 4.3."))
a(("bullet", "It is never written to the integration's own log output, which reports only the tenant and region."))
a(("bullet", "Rotate it in Sophos Central when the proof of concept ends, or whenever it may have been exposed."))

a(("h2", "9.4 Behaviour worth knowing"))
a(("table", ["Behaviour", "Why it matters"], [
    ["Only changes are emitted", "A quiet cycle produces no alerts. Absence of alerts is normal, not a failure"],
    ["Cursors are persistent", "Deleting the state file makes the integration re-fetch the last 12 hours, re-raising alerts for events already seen"],
    ["The API retains 24 hours", "If the manager is offline longer than that, the events from the gap are lost permanently. There is no backfill"],
    ["A token lasts one hour", "Each run authenticates independently, so a long outage has no lasting effect"],
    ["Read-only", "The integration cannot lock, wipe or otherwise act on a device"],
], [2700, 6660]))

# ---------------------------------------------------------------------- 10
a(("h1", "10. Troubleshooting"))
a(("table", ["Symptom", "Likely cause", "Action"], [
    ["Authentication fails with HTTP 401", "Wrong client ID or secret, or the credential was deleted in Sophos Central", "Re-create the credential and redeploy. The secret is shown only once and cannot be retrieved later"],
    [["Error mentioning ", ("idType", C)], "A partner or organization credential was used instead of a tenant credential", "Create the credential at tenant level"],
    [[("mobile/v1/devices", C), " returns 403 or 404"], "Sophos Mobile is not licensed or enabled on the tenant", "Expected on tenants without Sophos Mobile. The integration logs it and continues with the SIEM API"],
    ["HTTP 400 mentioning a limit", "The SIEM API requires a page size between 200 and 1000", "Do not lower the limit in the script below 200"],
    ["No alerts, but records exist in the log", "logcollector started tracking the file after it already had content", "See section 8.3. Reset the state file and re-run"],
    ["No records and no errors", "Nothing changed in Sophos since the last cycle", "Normal. Generate activity as described in section 8.3"],
    ["Manager does not restart after a rule change", "A malformed rule file", ["Run ", ("wazuh-analysisd -t", C), " to see the parse error. The installer performs this check before restarting"]],
    ["A rule never fires even though its condition is met", "A sibling rule with a higher level matched first", ["See section 5.1. Raise the level of the specific rule, and confirm with ", ("wazuh-logtest -v", C)]],
    [[("wazuh-manager", C), " shows as failed after a cold boot, but the daemons are running"], "The systemd unit timed out while starting, a known behaviour on the Wazuh OVA", ["Restart it once the indexer is active: ", ("systemctl restart wazuh-manager", C)]],
], [2300, 2900, 4160]))

# ---------------------------------------------------------------------- 11
a(("h1", "11. Limitations and next steps"))
a(("h2", "11.1 Current limitations"))
a(("bullet", "The Sophos SIEM API retains 24 hours of data. An outage longer than that loses the events in the gap, with no backfill mechanism."))
a(("bullet", "The mobile event type identifiers come from a public third-party ruleset rather than from Sophos documentation, so the list may be incomplete."))
a(("bullet", "Root, jailbreak and the configuration compliance rules are matched by text, because no event type identifier covers them."))
a(("bullet", "The internal structure of a compliance violation payload has not been observed and is handled generically."))
a(("bullet", "The installed applications endpoint does not return an application version, at least on Windows, so detection of vulnerable versions is not currently possible."))
a(("bullet", "Partner and organization level API credentials are not supported; the credential must be tenant scoped."))

a(("h2", "11.2 Next steps once an Android device is enrolled"))
a(("step", "Enrol an Android device and apply a compliance policy the device breaches, for example by forbidding an installed application or requiring a higher OS version."))
a(("step", ["Capture the resulting records from ", ("/var/log/sophos-mobile/events.json", C), "."]))
a(("step", ["Tighten rules ", ("100630", C), " to ", ("100640", C), " from text matching to the confirmed field names."]))
a(("step", "Extend the ruleset with any Android-specific event types the device produces, levelled so they beat the generic siblings as explained in section 5.1."))

# ---------------------------------------------------------------------- 12
a(("h1", "12. References"))
a(("link", "Sophos Central SIEM API documentation", "https://developer.sophos.com/docs/siem-v1/1/overview"))
a(("link", "Sophos Central API event and alert types (KBA-000006285)", "https://support.sophos.com/support/s/article/KBA-000006285"))
a(("link", "Sophos Mobile: available compliance rules", "https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/CompliancePolicies/AvailableComplianceRules/"))
a(("link", "Sophos Mobile: Mobile Threat Defense compliance rules", "https://docs.sophos.com/central/Mobile/help/en-us/AdminHelp/MTDWithIXM/ComplianceRules/index.html"))
a(("link", "Sophos mobile event type identifiers, quadrantsec/sagan-rules", "https://github.com/quadrantsec/sagan-rules/blob/main/sophos.rules"))
a(("link", "Wazuh: rules XML syntax", "https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html"))
a(("link", "Wazuh: collecting JSON log data", "https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html"))

# ============================================================== appendices
FILES = [
    ("A.1", "integration/custom-sophos-mobile.py", "Integration script"),
    ("A.2", "rules/sophos_mobile_rules.xml", "Detection rules"),
    ("A.3", "wazuh/ossec_conf_snippet.xml", "Wazuh manager configuration"),
    ("A.4", "deploy.sh", "Deployment script"),
    ("A.5", "setup-remote.sh", "Installer"),
    ("A.6", "tests/rule-tests.sh", "Rule test suite"),
]

a(("break",))
a(("h1", "Appendix A. Source code and configuration"))
a(("p", "Everything needed to reproduce the integration is reproduced verbatim below, read directly out "
        "of the repository when this document was generated, so it cannot drift from the code. The same "
        "files are delivered alongside this document; copying them from the archive rather than from "
        "these pages avoids any transcription problem, although text copied out of this document does "
        "preserve the original line structure."))
a(("table", ["Appendix", "File", "Contents", "Lines"],
   [[ap, [(rel, C)], desc, str(len(src(rel)))] for ap, rel, desc in FILES]
   + [["not printed", [("dashboard/sophos-mobile-dashboard.ndjson", C)],
       "Dashboard saved objects", "13 machine-generated objects"]],
   [1300, 3900, 2760, 1400]))
a(("callout", "Licensing.",
   "All files are released under the GNU General Public License version 2, the same license Wazuh itself "
   "uses, so this content is compatible with the Wazuh ruleset and integrations. The per-file notice at "
   "the top of each listing is part of that license and should be preserved in any modified copy."))

_NOTES = {
    "A.1": ["Installed as ", ("/var/ossec/integrations/custom-sophos-mobile.py", C),
            " with ownership ", ("root:wazuh", C), " and mode ", ("0750", C),
            ". The shebang points at the Python interpreter bundled with Wazuh, which already provides "
            "the ", ("requests", C), " library."],
    "A.2": ["Installed as ", ("/var/ossec/etc/rules/sophos_mobile_rules.xml", C),
            " with ownership ", ("wazuh:wazuh", C), " and mode ", ("0660", C),
            ". The header comment records which field names were verified against a live tenant, which "
            "were confirmed from a public ruleset, and which are matched by text, so that distinction "
            "survives in the file itself."],
    "A.3": ["These two blocks go inside ", ("<ossec_config>", C), " in ",
            ("/var/ossec/etc/ossec.conf", C), ". The installer appends them automatically and backs up "
            "the original file first; they are reproduced here for manual installations and for review."],
    "A.4": ["Run from the operator workstation. It reads the credentials from ", ("credentials.env", C),
            ", builds the configuration file, copies everything to the manager and runs the installer. "
            "The credential travels as a file rather than as a command-line argument, for the reason "
            "given in section 4.3."],
    "A.5": ["Executed as root on the Wazuh manager by the deployment script. It gates the restart on ",
            ("wazuh-analysisd -t", C), ", so a malformed ruleset cannot leave the manager down, and it "
            "securely deletes the temporary copy of the credential once installed."],
    "A.6": ["The suite referenced in section 8.2. Each case feeds one crafted record through ",
            ("wazuh-logtest", C), " and asserts which rule fires, so the Android detections can be "
            "validated before any Android device is enrolled. Run it as root on the manager."],
}

for ap, rel, desc in FILES:
    a(("break",))
    a(("h2", ap + " " + desc))
    a(("p", _NOTES[ap]))
    a(("srccode", src(rel), 7.0 if rel.endswith((".xml", ".sh")) else 7.5))
