#!/bin/bash
# setup-remote.sh - part of the Sophos Mobile to Wazuh integration
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
# Runs as root ON the Wazuh manager. Deployed by deploy.sh — do not run locally.
#
# Expects these to already be in /tmp (deploy.sh puts them there):
#   custom-sophos-mobile.py, sophos_mobile_rules.xml, sophos-mobile.json
set -e

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
PYTHON="$WAZUH_HOME/framework/python/bin/python3"

for f in /tmp/custom-sophos-mobile.py /tmp/sophos_mobile_rules.xml /tmp/sophos-mobile.json; do
  [ -f "$f" ] || { echo "!! $f missing — run deploy.sh, don't run this by hand."; exit 1; }
done

echo "[1/6] Installing integration script..."
install -o root -g wazuh -m 750 /tmp/custom-sophos-mobile.py \
  "$WAZUH_HOME/integrations/custom-sophos-mobile.py"

echo "[2/6] Installing rules..."
install -o wazuh -g wazuh -m 660 /tmp/sophos_mobile_rules.xml \
  "$WAZUH_HOME/etc/rules/sophos_mobile_rules.xml"

echo "[3/6] Installing credentials..."
install -o root -g wazuh -m 640 /tmp/sophos-mobile.json \
  "$WAZUH_HOME/etc/sophos-mobile.json"
# The /tmp copy carried the secret — destroy it rather than just unlinking.
shred -u /tmp/sophos-mobile.json 2>/dev/null || rm -f /tmp/sophos-mobile.json

mkdir -p /var/log/sophos-mobile
chown wazuh:wazuh /var/log/sophos-mobile

# Pre-create the output file EMPTY, before the manager restarts.
# When logcollector discovers a monitored file that already has content, it
# seeks to EOF and never reads what was already there — which silently drops
# the integration's first batch. Opening it at offset 0 avoids that.
[ -f /var/log/sophos-mobile/events.json ] || : > /var/log/sophos-mobile/events.json
chown wazuh:wazuh /var/log/sophos-mobile/events.json

echo "[4/6] Updating ossec.conf..."
if ! grep -q 'custom-sophos-mobile' "$WAZUH_HOME/etc/ossec.conf"; then
  cp "$WAZUH_HOME/etc/ossec.conf" "$WAZUH_HOME/etc/ossec.conf.bak-sophos"
  cat >> "$WAZUH_HOME/etc/ossec.conf" <<CONF

<ossec_config>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>sophos-mobile</tag>
    <command>$PYTHON $WAZUH_HOME/integrations/custom-sophos-mobile.py</command>
    <interval>5m</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>120</timeout>
  </wodle>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/sophos-mobile/events.json</location>
  </localfile>
</ossec_config>
CONF
else
  echo "  ossec.conf already configured, skipping."
fi

echo "[5/6] Validating ruleset and configuration..."
# Gate the restart: a bad rule file would otherwise stop the manager coming
# back up. wazuh-analysisd -t parses ossec.conf plus the full ruleset.
if ! "$WAZUH_HOME/bin/wazuh-analysisd" -t; then
  echo "!! Configuration test FAILED - not restarting the manager."
  echo "!! Fix the rules and re-run. Backup: $WAZUH_HOME/etc/ossec.conf.bak-sophos"
  exit 1
fi
echo "  configuration OK."

echo "[6/6] Running auth/fetch test..."
echo "===================== TEST OUTPUT ====================="
"$PYTHON" "$WAZUH_HOME/integrations/custom-sophos-mobile.py" --test
echo "======================================================="

rm -f /tmp/custom-sophos-mobile.py /tmp/sophos_mobile_rules.xml

echo "Restarting wazuh-manager..."
systemctl restart wazuh-manager
echo "DONE. Watch alerts with:"
echo "  tail -f $WAZUH_HOME/logs/alerts/alerts.json | grep sophos_mobile"
