#!/bin/bash
# Wazuh FIM Configuration Script
# Run as root

if [[ $EUID -ne 0 ]]; then
	   echo "Must run as root"
	      exit 1
fi

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [[ ! -f "$OSSEC_CONF" ]]; then
	    echo "Wazuh agent not found at $OSSEC_CONF"
	        exit 1
fi

# Backup existing config
cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"

# Check if syscheck already configured
if grep -q "<syscheck>" "$OSSEC_CONF"; then
	    # Remove existing syscheck block
	        sed -i '/<syscheck>/,/<\/syscheck>/d' "$OSSEC_CONF"
fi

# Insert new syscheck configuration before </ossec_config>
sed -i '/<\/ossec_config>/i\
	  <syscheck>\
	      <disabled>no</disabled>\
	          <frequency>300</frequency>\
		      <scan_on_start>yes</scan_on_start>\
		          \
			      <directories check_all="yes" realtime="yes">/etc</directories>\
			          <directories check_all="yes" realtime="yes">/usr/bin</directories>\
				      <directories check_all="yes" realtime="yes">/usr/sbin</directories>\
				          <directories check_all="yes" realtime="yes">/bin</directories>\
					      <directories check_all="yes" realtime="yes">/sbin</directories>\
					          <directories check_all="yes" realtime="yes">/root</directories>\
						      <directories check_all="yes" realtime="yes">/home</directories>\
						          \
							      <ignore>/etc/mtab</ignore>\
							          <ignore>/etc/resolv.conf</ignore>\
								      <ignore type="sregex">.log$</ignore>\
								        </syscheck>' "$OSSEC_CONF"

# Restart agent
if systemctl is-active --quiet wazuh-agent; then
	    systemctl restart wazuh-agent
	        echo "Wazuh agent restarted"
	elif [[ -x /var/ossec/bin/wazuh-control ]]; then
		    /var/ossec/bin/wazuh-control restart
		        echo "Wazuh agent restarted"
		else
			    echo "Unable to restart Wazuh agent"
			        exit 1
fi

# Force immediate scan
sleep 2
/var/ossec/bin/wazuh-syscheckd -f 2>/dev/null &

echo "FIM configured and scan initiated"
