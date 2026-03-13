#!/bin/bash
set -e
if [[ $EUID -ne 0 ]]; then
	           echo "This script must be run as root"
		                 exit 1
fi
echo "REMINDER: After password reset, clear your browser cache with CTRL + Shift + Delete before logging in."
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -a

