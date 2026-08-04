#!/var/ossec/framework/python/bin/python3
# custom-sophos-mobile.py
# Sophos Mobile / Sophos Central -> Wazuh integration
#
# Pulls these record kinds and writes them as JSON lines for Wazuh to ingest
# through a <localfile> json block:
#   1. siem/v1/events                             -> sophos_record=event
#   2. siem/v1/alerts                             -> sophos_record=alert
#   3. mobile/v1/devices                          -> sophos_record=device_status
#   4. mobile/v1/devices/{id}/compliance-violations
#                                                 -> sophos_record=compliance_violation
#   5. mobile/v1/devices/{id}/installed-apps      -> sophos_record=installed_app
#                                                    sophos_record=app_removed
#                                                    sophos_record=forbidden_app
#
# Endpoints verified against a live Sophos Central tenant (us03, 2026-08-03):
#   - The Sophos Mobile API is served at {dataRegion}/mobile/v1/... — NOT
#     /smc/v1/..., which returns 404 ApplicationNotFound on Central-managed
#     tenants.
#   - siem/v1 requires 200 <= limit <= 1000.
#   - siem/v1 cursors advance and do not re-deliver, so polling is safe.
#
# Config file (JSON): /var/ossec/etc/sophos-mobile.json
#   {"client_id": "...", "client_secret": "...",
#    "poll_installed_apps": true,          # optional, default true
#    "forbidden_apps": ["(?i)tiktok"]}     # optional regex list, default []
#
# Usage:
#   custom-sophos-mobile.py            # normal run (command wodle)
#   custom-sophos-mobile.py --test     # validate auth, print records to stdout
#
# State (cursors, device/violation hashes): /var/ossec/var/sophos-mobile.state

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not available. Install with: "
          "/var/ossec/framework/python/bin/pip3 install requests", file=sys.stderr)
    sys.exit(1)

CONFIG_FILE = "/var/ossec/etc/sophos-mobile.json"
STATE_FILE = "/var/ossec/var/sophos-mobile.state"
OUTPUT_FILE = "/var/log/sophos-mobile/events.json"
AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"
TIMEOUT = 30
TAG = "sophos_mobile"

SIEM_LIMIT = 1000        # API constraint: 200..1000
PAGE_SIZE = 500          # mobile/v1 constraint: pages.maxSize = 500
MAX_PAGES = 50           # runaway guard
FIRST_RUN_HOURS = 12     # SIEM API only retains 24h
MAX_TRACKED_VIOLATIONS = 200   # per device, keeps the state file bounded
MAX_APP_RECORDS = 50           # per device per run, guards against log floods

RECORD_NAME = {"events": "event", "alerts": "alert"}


def log(msg):
    print(f"{datetime.now(timezone.utc).isoformat()} sophos-mobile: {msg}",
          file=sys.stderr)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def digest(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True).encode()).hexdigest()


def authenticate(client_id, client_secret):
    r = requests.post(AUTH_URL, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "token",
    }, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["access_token"]


def whoami(token):
    r = requests.get(WHOAMI_URL,
                     headers={"Authorization": f"Bearer {token}"},
                     timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("idType") != "tenant":
        raise RuntimeError(f"Expected tenant credentials, got idType="
                           f"{data.get('idType')} (partner/organization "
                           "credentials need extra headers, not supported here)")
    return data["id"], data["apiHosts"]["dataRegion"]


def emit(out, record_type, payload):
    out.append({
        "integration": TAG,
        "sophos_record": record_type,
        "sophos": payload,
    })


def fetch_siem(host, headers, endpoint, state, out):
    """Fetch siem/v1/{events,alerts} using the stored cursor."""
    key = f"cursor_{endpoint}"
    params = {"limit": SIEM_LIMIT}
    if state.get(key):
        params["cursor"] = state[key]
    else:
        params["from_date"] = int(
            (datetime.now(timezone.utc)
             - timedelta(hours=FIRST_RUN_HOURS)).timestamp())

    total = 0
    for _ in range(MAX_PAGES):
        r = requests.get(f"{host}/siem/v1/{endpoint}",
                         headers=headers, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        for item in data.get("items", []):
            emit(out, RECORD_NAME[endpoint], item)
            total += 1
        cursor = data.get("next_cursor")
        if cursor:
            state[key] = cursor
        # Without a cursor there is nothing to page with, so stop regardless.
        if not data.get("has_more") or not cursor:
            break
        params = {"limit": SIEM_LIMIT, "cursor": cursor}
    log(f"{endpoint}: {total} new items")


def get_paged(host, headers, path):
    """Collect all items from a paginated mobile/v1 collection."""
    items = []
    for page in range(1, MAX_PAGES + 1):
        r = requests.get(f"{host}{path}", headers=headers,
                         params={"pageSize": PAGE_SIZE, "page": page,
                                 "pageTotal": "true"},
                         timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        batch = data.get("items", [])
        items.extend(batch)
        pages = data.get("pages", {})
        total = pages.get("total")
        if total is not None:
            if len(items) >= total:
                break
        elif len(batch) < PAGE_SIZE:
            break
    return items


def fetch_devices(host, headers, state, out, cfg):
    """Poll the Sophos Mobile inventory; emit only on change."""
    try:
        devices = get_paged(host, headers, "/mobile/v1/devices")
    except requests.HTTPError as e:
        # 403/404 -> Sophos Mobile not licensed/enabled for this tenant
        log(f"mobile/v1/devices not available "
            f"({e.response.status_code}), skipping device polling")
        return

    known = state.setdefault("device_hashes", {})
    changed = 0
    for dev in devices:
        dev_id = str(dev.get("id") or dev.get("name") or "unknown")
        dig = digest(dev)
        if known.get(dev_id) != dig:
            known[dev_id] = dig
            emit(out, "device_status", dev)
            changed += 1
    log(f"devices: {len(devices)} total, {changed} new/changed")

    fetch_violations(host, headers, devices, state, out)
    if cfg.get("poll_installed_apps", True):
        fetch_apps(host, headers, devices, state, out, cfg)


def fetch_violations(host, headers, devices, state, out):
    """Emit each newly seen compliance violation once, per device."""
    seen = state.setdefault("violation_hashes", {})
    new = 0
    for dev in devices:
        dev_id = str(dev.get("id") or "unknown")
        try:
            violations = get_paged(
                host, headers,
                f"/mobile/v1/devices/{dev_id}/compliance-violations")
        except requests.HTTPError as e:
            log(f"compliance-violations for {dev_id} unavailable "
                f"({e.response.status_code}), skipping")
            continue

        prev = seen.get(dev_id, [])
        current = []
        for v in violations:
            dig = digest(v)
            current.append(dig)
            if dig not in prev:
                emit(out, "compliance_violation", {
                    "deviceId": dev_id,
                    "deviceName": dev.get("name"),
                    "os": dev.get("os", {}),
                    "violation": v,
                    # The exact field names Sophos uses here could not be
                    # verified (this tenant has no active violations), so the
                    # whole payload is also flattened into one searchable
                    # string. Rules match on this instead of guessing keys.
                    "violationText": json.dumps(v, sort_keys=True),
                })
                new += 1
        # Keep hashes still present, so a cleared-then-reappearing violation
        # is reported again, and cap the list to bound the state file.
        seen[dev_id] = current[-MAX_TRACKED_VIOLATIONS:]
    log(f"compliance violations: {new} new")


def compile_forbidden(cfg):
    patterns = []
    for p in cfg.get("forbidden_apps") or []:
        try:
            patterns.append(re.compile(p))
        except re.error as e:
            log(f"ignoring invalid forbidden_apps regex {p!r}: {e}")
    return patterns


def fetch_apps(host, headers, devices, state, out, cfg):
    """Track installed apps per device: report installs, removals, and any app
    matching cfg['forbidden_apps'].

    The first time a device is seen its app list is recorded as a baseline
    WITHOUT emitting records — otherwise every enrolled device would dump its
    entire inventory (100+ apps on Windows) into Wazuh on the first run.
    Forbidden-app matching does run on that first pass, since an already
    installed prohibited app is exactly what needs reporting.
    """
    forbidden = compile_forbidden(cfg)
    baseline = state.setdefault("app_ids", {})
    flagged = state.setdefault("forbidden_seen", {})
    installed = removed = bad = 0

    for dev in devices:
        dev_id = str(dev.get("id") or "unknown")
        try:
            apps = get_paged(
                host, headers, f"/mobile/v1/devices/{dev_id}/installed-apps")
        except requests.HTTPError as e:
            log(f"installed-apps for {dev_id} unavailable "
                f"({e.response.status_code}), skipping")
            continue

        by_id = {}
        for a in apps:
            ident = str(a.get("identifier") or a.get("name") or "unknown")
            by_id[ident] = a

        meta = {"deviceId": dev_id, "deviceName": dev.get("name"),
                "os": dev.get("os", {})}
        prev = set(baseline.get(dev_id, []))
        cur = set(by_id)

        if dev_id not in baseline:
            log(f"apps: baseline of {len(cur)} apps recorded for "
                f"{dev.get('name')} (not alerted)")
        else:
            for ident in sorted(cur - prev)[:MAX_APP_RECORDS]:
                emit(out, "installed_app", dict(meta, app=by_id[ident],
                                                appIdentifier=ident,
                                                appName=by_id[ident].get("name")))
                installed += 1
            for ident in sorted(prev - cur)[:MAX_APP_RECORDS]:
                emit(out, "app_removed", dict(meta, appIdentifier=ident))
                removed += 1

        baseline[dev_id] = sorted(cur)

        # Re-checked every run, but only reported once while the app stays
        # installed; pruning to `cur` means a reinstall alerts again.
        seen = set(flagged.get(dev_id, []))
        for ident, app in sorted(by_id.items()):
            if ident in seen:
                continue
            haystack = f"{ident} {app.get('name', '')}"
            hit = next((rx for rx in forbidden if rx.search(haystack)), None)
            if hit:
                emit(out, "forbidden_app", dict(meta, app=app,
                                                appIdentifier=ident,
                                                appName=app.get("name"),
                                                matchedPattern=hit.pattern))
                seen.add(ident)
                bad += 1
        flagged[dev_id] = sorted(seen & cur)

    log(f"apps: {installed} installed, {removed} removed, {bad} forbidden")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true",
                        help="validate auth and print output to stdout")
    args = parser.parse_args()

    cfg = load_json(CONFIG_FILE, None)
    if not cfg or not cfg.get("client_id") or not cfg.get("client_secret"):
        log(f"missing credentials in {CONFIG_FILE}")
        sys.exit(1)

    state = {} if args.test else load_json(STATE_FILE, {})
    out = []

    try:
        token = authenticate(cfg["client_id"], cfg["client_secret"])
        tenant_id, data_region = whoami(token)
        log(f"authenticated OK, tenant={tenant_id}, region={data_region}")
        headers = {"Authorization": f"Bearer {token}",
                   "X-Tenant-ID": tenant_id}

        fetch_siem(data_region, headers, "events", state, out)
        fetch_siem(data_region, headers, "alerts", state, out)
        fetch_devices(data_region, headers, state, out, cfg)
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)

    if args.test:
        for rec in out:
            print(json.dumps(rec))
        log(f"test OK: {len(out)} records (state not saved)")
        return

    if out:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "a") as f:
            for rec in out:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    save_state(state)
    log(f"wrote {len(out)} records to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
