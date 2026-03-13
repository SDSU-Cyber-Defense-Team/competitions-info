#!/bin/bash
# =============================================================================
# Wazuh CCDC Quick Deploy
# Imports dashboards, custom rules, and creates per-agent dashboards
# Run this on the Wazuh server after a fresh install
#
# Usage: ./wazuh_deploy.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==========================================="
echo "  Wazuh CCDC Dashboard & Rules Deployment"
echo "==========================================="
echo ""

read -p "Dashboard username [admin]: " DASH_USER
DASH_USER="${DASH_USER:-admin}"
read -sp "[wazuh] password for $DASH_USER: " DASH_PASS
echo
echo ""

CREDS="${DASH_USER}:${DASH_PASS}"

# --- Step 1: Import custom detection rules ---
echo "[1/4] Installing custom detection rules..."

RULES_FILE="${SCRIPT_DIR}/local_rules.xml"
if [ -f "$RULES_FILE" ]; then
  cp "$RULES_FILE" /var/ossec/etc/rules/local_rules.xml
  chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
  chmod 660 /var/ossec/etc/rules/local_rules.xml
  echo "  [+] Custom rules installed"
else
  echo "  [!] local_rules.xml not found in ${SCRIPT_DIR}, skipping"
fi

# --- Step 2: Restart Wazuh manager to load rules ---
echo "[2/4] Restarting Wazuh manager..."
systemctl restart wazuh-manager 2>/dev/null
if [ $? -eq 0 ]; then
  echo "  [+] Manager restarted"
else
  echo "  [!] Manager restart failed - check /var/ossec/logs/ossec.log"
fi

# --- Step 3: Import dashboards and visualizations ---
echo "[3/4] Importing dashboards and visualizations..."

EXPORT_FILE="${SCRIPT_DIR}/wazuh_dashboards_export.ndjson"
if [ ! -f "$EXPORT_FILE" ]; then
  echo "  [!] ${EXPORT_FILE} not found"
  exit 1
fi

# Wait for dashboard to be ready
echo "  [*] Waiting for dashboard to be ready..."
for i in $(seq 1 30); do
  HEALTH=$(curl -sk -u "${CREDS}" -o /dev/null -w "%{http_code}" "https://localhost/api/status" -H 'osd-xsrf: true' 2>/dev/null)
  if [ "$HEALTH" = "200" ]; then
    break
  fi
  sleep 2
done

RESULT=$(curl -sk -u "${CREDS}" \
  -X POST "https://localhost/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' \
  -F "file=@${EXPORT_FILE}" 2>/dev/null)

if echo "$RESULT" | grep -q '"success":true'; then
  COUNT=$(echo "$RESULT" | sed -n 's/.*"successCount":\([0-9]*\).*/\1/p')
  echo "  [+] Imported ${COUNT} objects"
else
  echo "  [!] Import failed:"
  echo "  $RESULT" | head -c 300
  echo
fi

# --- Step 4: Create per-agent dashboards ---
echo "[4/4] Creating per-agent dashboards..."

# Find the master dashboard
ALL_DASHBOARDS=$(curl -sk -u "${CREDS}" -H 'osd-xsrf: true' \
  "https://localhost/api/saved_objects/_find?type=dashboard&per_page=100")
ALL_IDS=$(echo "$ALL_DASHBOARDS" | grep -o '"type":"dashboard","id":"[^"]*"' | sed 's/.*"id":"\([^"]*\)".*/\1/')

MASTER_ID=""
for DID in $ALL_IDS; do
  D=$(curl -sk -u "${CREDS}" -H 'osd-xsrf: true' \
    "https://localhost/api/saved_objects/dashboard/${DID}")
  T=$(echo "$D" | grep -o '"title":"[^"]*"' | head -1 | sed 's/"title":"\([^"]*\)"/\1/')
  if [ "$T" = "master" ]; then
    MASTER_ID="$DID"
    MASTER_DASH="$D"
    break
  fi
done

if [ -z "$MASTER_ID" ]; then
  echo "  [!] Master dashboard not found, skipping per-agent dashboards"
  echo ""
  echo "[*] Deployment complete! Open the Wazuh dashboard to verify."
  exit 0
fi

PANELS=$(echo "$MASTER_DASH" | sed 's/.*"panelsJSON":"//' | sed 's/","optionsJSON".*//' | head -1)
OPTIONS=$(echo "$MASTER_DASH" | sed 's/.*"optionsJSON":"//' | sed 's/","version".*//' | head -1)
REFS=$(echo "$MASTER_DASH" | sed 's/.*"references":\[//' | sed 's/\],"migrationVersion".*//' | sed 's/\],"updated_at".*//' | head -1)

# Discover agents
AGENTS_RAW=$(curl -sk -u "${CREDS}" -H 'osd-xsrf: true' \
  -H 'Content-Type: application/json' \
  "https://localhost/api/console/proxy?path=wazuh-alerts-*/_search&method=POST" \
  -d '{"size":0,"aggs":{"agents":{"terms":{"field":"agent.name","size":200}}}}')

AGENTS=$(echo "$AGENTS_RAW" | sed 's/,/\n/g' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')

if [ -z "$AGENTS" ]; then
  echo "  [*] No agents reporting yet - run duplicate_dashboard.sh later once agents connect"
else
  # Get existing dashboard titles
  EXISTING_TITLES=""
  for DID in $ALL_IDS; do
    D=$(curl -sk -u "${CREDS}" -H 'osd-xsrf: true' \
      "https://localhost/api/saved_objects/dashboard/${DID}")
    T=$(echo "$D" | grep -o '"title":"[^"]*"' | head -1 | sed 's/"title":"\([^"]*\)"/\1/')
    EXISTING_TITLES="${EXISTING_TITLES}${T}\n"
  done

  CREATED=0
  for AGENT in $AGENTS; do
    if echo -e "$EXISTING_TITLES" | grep -qx "$AGENT"; then
      echo "  [-] '${AGENT}' already exists, skipping"
      continue
    fi

    cat > /tmp/wazuh_dup_payload.json <<DUPPAYLOAD
{
  "attributes": {
    "title": "${AGENT}",
    "hits": 0,
    "description": "Copy of 'master' filtered for agent: ${AGENT}",
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

    RESULT=$(curl -sk -u "${CREDS}" -H 'osd-xsrf: true' \
      -H 'Content-Type: application/json' \
      -X POST "https://localhost/api/saved_objects/dashboard" \
      -d @/tmp/wazuh_dup_payload.json)

    NEW_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"\([^"]*\)"/\1/')
    if [ -n "$NEW_ID" ]; then
      echo "  [+] Created '${AGENT}'"
      CREATED=$((CREATED + 1))
    else
      echo "  [!] Failed for ${AGENT}"
    fi
  done
  echo "  [+] Created ${CREATED} agent dashboards"
fi

echo ""
echo "==========================================="
echo "  Deployment complete!"
echo "==========================================="
echo ""
echo "  Dashboards: https://localhost → Dashboards"
echo "  Custom rules: /var/ossec/etc/rules/local_rules.xml"
echo ""
echo "  If new agents connect later, run:"
echo "    ./duplicate_dashboard.sh master"
echo "==========================================="
