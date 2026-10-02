#!/usr/bin/env sh
set -eu

mkdir -p /tmp/ccdc/modules

#DROP ../modules/failsafe_creator.sh /tmp/ccdc/modules/failsafe_creator.sh
#DROP ../modules/copyfail_patcher.sh /tmp/ccdc/modules/copyfail_patcher.sh
#DROP ../modules/dirtyfrag_patcher.sh /tmp/ccdc/modules/dirtyfrag_patcher.sh
#DROP ../modules/root_locker.sh /tmp/ccdc/modules/root_locker.sh
#DROP ../modules/user_locker.sh /tmp/ccdc/modules/user_locker.sh
#DROP ../run_all.sh /tmp/ccdc/run_all.sh
#DROP allowlist.txt /tmp/ccdc/allowlist.txt

chmod 700 /tmp/ccdc/run_all.sh /tmp/ccdc/modules/*.sh
sh /tmp/ccdc/run_all.sh "$@" /tmp/ccdc/allowlist.txt
