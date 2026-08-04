#!/bin/bash
# Deploy the Sophos Mobile -> Wazuh integration to a Wazuh manager over SSH.
#
#   cp credentials.env.example credentials.env   # then fill it in
#   bash deploy.sh wazuh-user@wazuh-manager.example.com
#
# The credentials are written to a temp file and copied with scp, never passed
# as a command-line argument: on many hosts journald records sudo command lines
# and Wazuh's own rule 5402 would turn them into alerts containing the secret.
set -euo pipefail

TARGET="${1:-wazuh-user@wazuh-manager.example.com}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ENVF="$DIR/credentials.env"

if [ ! -f "$ENVF" ]; then
  echo "!! $ENVF not found."
  echo "!! Run: cp credentials.env.example credentials.env   and fill it in."
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENVF"
set +a

: "${SOPHOS_CLIENT_ID:?set SOPHOS_CLIENT_ID in credentials.env}"
: "${SOPHOS_CLIENT_SECRET:?set SOPHOS_CLIENT_SECRET in credentials.env}"
if [ "$SOPHOS_CLIENT_SECRET" = "replace-me" ]; then
  echo "!! SOPHOS_CLIENT_SECRET is still the placeholder value."
  exit 1
fi

POLL="${SOPHOS_POLL_INSTALLED_APPS:-true}"
FORBIDDEN="${SOPHOS_FORBIDDEN_APPS:-[]}"

CFG="$(mktemp)"
chmod 600 "$CFG"
trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<EOF
{"client_id": "$SOPHOS_CLIENT_ID",
 "client_secret": "$SOPHOS_CLIENT_SECRET",
 "poll_installed_apps": $POLL,
 "forbidden_apps": $FORBIDDEN}
EOF

python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$CFG" 2>/dev/null || {
  echo "!! The generated config is not valid JSON — check SOPHOS_FORBIDDEN_APPS."
  echo "!! It must be a JSON array, e.g. [\"(?i)tiktok\"]"
  exit 1
}

echo ">> Copying files to $TARGET..."
scp -q "$DIR/integration/custom-sophos-mobile.py" \
       "$DIR/rules/sophos_mobile_rules.xml" \
       "$DIR/setup-remote.sh" \
       "$TARGET:/tmp/"
scp -q "$CFG" "$TARGET:/tmp/sophos-mobile.json"

echo ">> Running remote setup (sudo password may be prompted)..."
ssh -t "$TARGET" "chmod 600 /tmp/sophos-mobile.json && sudo bash /tmp/setup-remote.sh"

echo
echo ">> Optional: load the dashboard (run on the Wazuh node)"
echo "   scp dashboard/sophos-mobile-dashboard.ndjson dashboard/load-dashboard.sh $TARGET:/tmp/"
echo "   ssh $TARGET 'sudo bash /tmp/load-dashboard.sh /tmp/sophos-mobile-dashboard.ndjson'"
