#!/bin/bash
# =============================================================================
# Wazuh Dashboard Import Script
# Imports dashboards & visualizations from an NDJSON export file
#
# Usage: ./wazuh_import_dashboards.sh [export_file]
# Default export file: /root/wazuh_dashboards_export.ndjson
# =============================================================================

FILE="${1:-/root/wazuh_dashboards_export.ndjson}"

read -p "Dashboard username [admin]: " DASH_USER
DASH_USER="${DASH_USER:-admin}"
read -sp "[wazuh] password for $DASH_USER: " DASH_PASS
echo

if [ ! -f "$FILE" ]; then
  echo "[!] Export file not found: $FILE"
  exit 1
fi

echo "[*] Importing from $FILE ..."

RESULT=$(curl -sk -u "${DASH_USER}:${DASH_PASS}" \
  -X POST "https://localhost/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' \
  -F "file=@${FILE}" 2>/dev/null)

if echo "$RESULT" | grep -q '"success":true'; then
  COUNT=$(echo "$RESULT" | sed -n 's/.*"successCount":\([0-9]*\).*/\1/p')
  echo "[+] Success! Imported ${COUNT} objects."
else
  echo "[!] Import failed:"
  echo "$RESULT"
  exit 1
fi
