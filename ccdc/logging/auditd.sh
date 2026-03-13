#!/bin/bash

# Root check
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Detect distro family
if command -v apk &>/dev/null; then
    PKG_MGR="apk"
elif command -v apt &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    echo "Error: Unsupported package manager. This script supports apk, apt, dnf, and yum." >&2
    exit 1
fi

echo "Detected package manager: $PKG_MGR"

# Update and install auditd
case "$PKG_MGR" in
    apk)
        apk update && apk upgrade
        apk add audit
        RULES_FILE="/etc/audit/audit.rules"
        INIT_SYS="openrc"
        ;;
    apt)
        apt update && apt upgrade -y
        apt install -y auditd
        RULES_FILE="/etc/audit/audit.rules"
        INIT_SYS="systemd"
        ;;
    dnf)
        dnf upgrade -y
        dnf install -y audit
        RULES_FILE="/etc/audit/rules.d/wazuh.rules"
        INIT_SYS="systemd"
        ;;
    yum)
        yum update -y
        yum install -y audit
        RULES_FILE="/etc/audit/rules.d/wazuh.rules"
        INIT_SYS="systemd"
        ;;
esac

# Enable and start auditd based on init system
if [[ "$INIT_SYS" == "openrc" ]]; then
    rc-update add auditd default
    rc-service auditd start
    rc-service auditd status
else
    systemctl enable --now auditd
    systemctl status auditd --no-pager
fi

# Define audit rules
RULE_64="-a exit,always -F arch=b64 -S execve -F auid>=0 -F auid!=-1 -k audit-wazuh-c"
RULE_32="-a exit,always -F arch=b32 -S execve -F auid>=0 -F auid!=-1 -k audit-wazuh-c"

# Ensure rules directory exists for RHEL-based systems
mkdir -p "$(dirname "$RULES_FILE")"

# Append rules only if not already present
grep -qxF "$RULE_64" "$RULES_FILE" 2>/dev/null || echo "$RULE_64" >> "$RULES_FILE"
grep -qxF "$RULE_32" "$RULES_FILE" 2>/dev/null || echo "$RULE_32" >> "$RULES_FILE"

# Reload audit rules
case "$PKG_MGR" in
    apk|apt)
        auditctl -R "$RULES_FILE"
        ;;
    dnf|yum)
        augenrules --load
        ;;
esac

echo "auditd configured successfully on $PKG_MGR-based system."
