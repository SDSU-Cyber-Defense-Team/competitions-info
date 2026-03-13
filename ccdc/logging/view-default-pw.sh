#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
	   echo "This script must be run as root"
	      exit 1
fi

tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
