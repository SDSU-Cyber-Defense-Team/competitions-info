#!/bin/bash
# =============================================================================
# Wazuh Dashboard Duplicator
# Copies any dashboard and creates a per-agent filtered version for each agent
#
# Usage: ./duplicate_dashboard.sh <dashboard_title>
#
# Examples:
#   ./duplicate_dashboard.sh master
# =============================================================================

DASHBOARD_TITLE="${1:?Usage: $0 <dashboard_title>}"

read -p "Dashboard username [admin]: " DASH_USER
DASH_USER="${DASH_USER:-admin}"
read -sp "[wazuh] password for $DASH_USER: " DASH_PASS
echo

CREDS="${DASH_USER}:${DASH_PASS}"
URL="https://localhost"

api() {
  curl -sk -u "$CREDS" -H 'osd-xsrf: true' "$@"
}

# --- Find the source dashboard ---
echo "[*] Searching for dashboard: ${DASHBOARD_TITLE}"

ALL_DASHBOARDS=$(api "${URL}/api/saved_objects/_find?type=dashboard&per_page=100")
ALL_IDS=$(echo "$ALL_DASHBOARDS" | grep -o '"type":"dashboard","id":"[^"]*"' | sed 's/.*"id":"\([^"]*\)".*/\1/')

DASHBOARD_ID=""
for DID in $ALL_IDS; do
  D=$(api "${URL}/api/saved_objects/dashboard/${DID}")
  T=$(echo "$D" | grep -o '"title":"[^"]*"' | head -1 | sed 's/"title":"\([^"]*\)"/\1/')
  if [ "$T" = "$DASHBOARD_TITLE" ]; then
    DASHBOARD_ID="$DID"
    DASHBOARD="$D"
    break
  fi
done

if [ -z "$DASHBOARD_ID" ]; then
  echo "[!] Dashboard '${DASHBOARD_TITLE}' not found."
  echo "[*] Available dashboards:"
  for DID in $ALL_IDS; do
    D=$(api "${URL}/api/saved_objects/dashboard/${DID}")
    T=$(echo "$D" | grep -o '"title":"[^"]*"' | head -1 | sed 's/"title":"\([^"]*\)"/\1/')
    echo "  - $T"
  done
  exit 1
fi

echo "[+] Found: ${DASHBOARD_ID}"

# --- Parse dashboard ---
PANELS=$(echo "$DASHBOARD" | sed 's/.*"panelsJSON":"//' | sed 's/","optionsJSON".*//' | head -1)
OPTIONS=$(echo "$DASHBOARD" | sed 's/.*"optionsJSON":"//' | sed 's/","version".*//' | head -1)
REFS=$(echo "$DASHBOARD" | sed 's/.*"references":\[//' | sed 's/\],"migrationVersion".*//' | sed 's/\],"updated_at".*//' | head -1)

if [ -z "$PANELS" ]; then
  echo "[!] Could not parse dashboard panels."
  exit 1
fi

# --- Discover agents ---
echo "[*] Discovering agents..."

AGENTS_RAW=$(api \
  "${URL}/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"aggs":{"agents":{"terms":{"field":"agent.name","size":200}}}}')

AGENTS=$(echo "$AGENTS_RAW" | sed 's/,/\n/g' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')

if [ -z "$AGENTS" ]; then
  echo "[!] No agents found in wazuh-alerts index."
  exit 1
fi

AGENT_COUNT=$(echo "$AGENTS" | wc -l)
echo "[+] Found ${AGENT_COUNT} agents:"
echo "$AGENTS" | sed 's/^/    /'
echo ""

# --- Check existing dashboards ---
EXISTING_TITLES=""
for DID in $ALL_IDS; do
  D=$(api "${URL}/api/saved_objects/dashboard/${DID}")
  T=$(echo "$D" | grep -o '"title":"[^"]*"' | head -1 | sed 's/"title":"\([^"]*\)"/\1/')
  EXISTING_TITLES="${EXISTING_TITLES}${T}\n"
done

CREATED=0
SKIPPED=0

for AGENT in $AGENTS; do
  if echo -e "$EXISTING_TITLES" | grep -qx "$AGENT"; then
    echo "[-] '${AGENT}' already exists, skipping."
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  echo "[*] Creating: ${AGENT}"

  cat > /tmp/wazuh_dup_payload.json <<DUPPAYLOAD
{
  "attributes": {
    "title": "${AGENT}",
    "hits": 0,
    "description": "Copy of '${DASHBOARD_TITLE}' filtered for agent: ${AGENT}",
    "panelsJSON": "${PANELS}",
    "optionsJSON": "${OPTIONS}",
    "version": 1,
    "timeRestore": false,
    "kibanaSavedObjectMeta": {
      "searchSourceJSON": "{\"query\":{\"language\":\"kuery\",\"query\":\"agent.name: ${AGENT}\"},\"filter\":[]}"
    }
  },
  "references": [${REFS}]
}
DUPPAYLOAD

  RESULT=$(api -X POST "${URL}/api/saved_objects/dashboard" \
    -H 'Content-Type: application/json' \
    -d @/tmp/wazuh_dup_payload.json)

  NEW_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"\([^"]*\)"/\1/')
  if [ -n "$NEW_ID" ]; then
    echo "    [+] Created - ID: ${NEW_ID}"
    CREATED=$((CREATED + 1))
  else
    echo "    [!] Failed"
    echo "    $RESULT" | head -c 200
    echo
  fi
done

echo ""
echo "[*] Done! Created: ${CREATED}, Skipped: ${SKIPPED}"
