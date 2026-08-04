#!/bin/bash
# Import the Sophos Mobile dashboard into Wazuh Dashboards (OpenSearch
# Dashboards) via the saved-objects API. Run ON the Wazuh node, as root.
#
#   bash load-dashboard.sh [ndjson] [dashboard-url] [user] [password]
#
# Regenerate the ndjson first if you changed make_dashboard.py:
#   python3 make_dashboard.py sophos-mobile-dashboard.ndjson
#
# Only the 12 panels + 1 saved search are created; the stock "wazuh-alerts-*"
# index pattern is referenced, never modified.
set -e

NDJSON="${1:-/tmp/sophos-mobile-dashboard.ndjson}"
URL="${2:-https://localhost}"
USER="${3:-admin}"
PASS="${4:-admin}"
PY=/var/ossec/framework/python/bin/python3

[ -f "$NDJSON" ] || { echo "!! $NDJSON not found"; exit 1; }

echo ">> Checking the referenced index pattern exists..."
if ! curl -sk -u "$USER:$PASS" \
     "$URL/api/saved_objects/index-pattern/wazuh-alerts-*" \
     | grep -q '"id"'; then
  echo "!! index pattern 'wazuh-alerts-*' not found on this dashboard."
  echo "!! Open Wazuh once so it gets created, or pass a different id to"
  echo "!! make_dashboard.py and regenerate."
  exit 1
fi

echo ">> Importing saved objects..."
RESP=$(curl -sk -u "$USER:$PASS" -X POST \
  "$URL/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" -F "file=@$NDJSON")

echo "$RESP" | $PY -c '
import sys, json
d = json.load(sys.stdin)
print("   success:", d.get("success"), " imported:", d.get("successCount"))
for e in d.get("errors", []) or []:
    print("   ERROR", e.get("type"), e.get("id"), e.get("error"))
sys.exit(0 if d.get("success") else 1)
'

echo
echo "DONE. Open it at:"
echo "  <dashboard-host>/app/dashboards#/view/sophos-mobile-dashboard"
echo "Or filter any Wazuh view with:  rule.groups:sophos_mobile"
