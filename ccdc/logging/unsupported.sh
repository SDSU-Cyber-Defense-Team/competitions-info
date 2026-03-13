#!/bin/bash

# This script is to be ran on OS's that aren't supported by Wazuh out of the box.

read -p "Enter agent name: " AGENT_NAME
read -p "Enter Wazuh manager IP: " MANAGER_IP

# Install Docker if not present
which docker &>/dev/null || {
  command -v apk &>/dev/null && apk add docker && rc-service docker start && rc-update add docker default
  command -v apt &>/dev/null && apt install -y docker.io
  command -v dnf &>/dev/null && dnf install -y docker && systemctl enable --now docker
  command -v yum &>/dev/null && yum install -y docker && systemctl enable --now docker
  command -v xbps-install &>/dev/null && xbps-install -Sy docker && ln -s /etc/sv/docker /var/service/ && sv start docker
}

docker rm -f wazuh-agent 2>/dev/null

docker run -d --name wazuh-agent \
  --hostname "$AGENT_NAME" \
  --network host \
  -v /var/log:/var/log:ro \
  -v /etc:/etc/host:ro \
  -v /bin:/host/bin:ro \
  -v /sbin:/host/sbin:ro \
  -v /usr:/host/usr:ro \
  -v /home:/host/home:ro \
  -v /root:/host/root:ro \
  -v /tmp:/host/tmp:ro \
  wazuh/wazuh-agent:4.14.3

docker exec wazuh-agent sh -c 'echo "" > /var/ossec/etc/client.keys'
docker exec wazuh-agent sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|" /var/ossec/etc/ossec.conf
docker exec wazuh-agent /var/ossec/bin/agent-auth -m "$MANAGER_IP" -A "$AGENT_NAME"

docker exec wazuh-agent sed -i '/<syscheck>/,/<\/syscheck>/c \
<syscheck>\n  <disabled>no</disabled>\n  <frequency>300</frequency>\n  <directories check_all="yes" realtime="yes">/host/bin</directories>\n  <directories check_all="yes" realtime="yes">/host/sbin</directories>\n  <directories check_all="yes" realtime="yes">/host/usr/bin</directories>\n  <directories check_all="yes" realtime="yes">/host/usr/sbin</directories>\n  <directories check_all="yes" realtime="yes">/etc/host</directories>\n  <directories check_all="yes" realtime="yes">/host/home</directories>\n  <directories check_all="yes" realtime="yes">/host/root</directories>\n</syscheck>' /var/ossec/etc/ossec.conf

docker exec wazuh-agent sed -i '/<\/ossec_config>/i \
<localfile>\n  <log_format>audit</log_format>\n  <location>/var/log/audit/audit.log</location>\n</localfile>' /var/ossec/etc/ossec.conf

docker exec wazuh-agent /var/ossec/bin/wazuh-control restart

echo "Wazuh agent '$AGENT_NAME' deployed and connected to $MANAGER_IP"
