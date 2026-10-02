#!/usr/bin/env sh
set -eu

log() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

fail() {
    printf '[x] %s\n' "$*" >&2
    exit 1
}

need_root() {
    [ "$(id -u)" -eq 0 ] || fail "This script must be run as root."
}

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

backup_file() {
    backup_file_path=$1
    backup_ts=$(date +%Y%m%d-%H%M%S 2> /dev/null || echo backup)
    cp -p -- "$backup_file_path" "$backup_file_path.bak.$backup_ts"
}

#
# Lock root password authentication using common account tools.
#
lock_root_password() {
    if command_exists passwd; then
        if passwd -l root > /dev/null 2>&1; then
            log "Locked root password with passwd -l."
            return
        fi
    fi

    if command_exists usermod; then
        if usermod -L root > /dev/null 2>&1; then
            log "Locked root password with usermod -L."
            return
        fi
    fi

    warn "Could not lock root password automatically."
}

#
# Clear root SSH authorized key files after taking timestamped backups.
#
remove_root_ssh_keys() {
    remove_ssh_dir=/root/.ssh
    remove_auth_keys=$remove_ssh_dir/authorized_keys
    remove_auth_keys2=$remove_ssh_dir/authorized_keys2

    if [ -f "$remove_auth_keys" ]; then
        backup_file "$remove_auth_keys"
        : > "$remove_auth_keys"
        chmod 600 "$remove_auth_keys" || true
        log "Cleared root authorized_keys."
    else
        log "No root authorized_keys file found."
    fi

    if [ -f "$remove_auth_keys2" ]; then
        backup_file "$remove_auth_keys2"
        : > "$remove_auth_keys2"
        chmod 600 "$remove_auth_keys2" || true
        log "Cleared root authorized_keys2."
    fi
}

#
# Return true when sshd_config includes the drop-in config directory.
#
sshd_config_includes_dropins() {
    sshd_config_includes_path=$1

    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*Include[[:space:]]/ && /sshd_config\.d/ { found=1 }
        END { exit(found ? 0 : 1) }
    ' "$sshd_config_includes_path"
}

#
# Write a drop-in that disables SSH root login.
#
write_sshd_dropin() {
    write_dropin_config_path=$1
    write_dropin_dir=$(dirname "$write_dropin_config_path")/sshd_config.d
    write_dropin_path=$write_dropin_dir/99-disable-root-login.conf

    mkdir -p "$write_dropin_dir"

    cat > "$write_dropin_path" << 'EOF'
# Managed by root lockdown script
PermitRootLogin no
EOF

    chmod 644 "$write_dropin_path"
    log "Wrote SSH drop-in: $write_dropin_path"
}

#
# Update the main sshd_config when drop-ins are not included.
#
write_sshd_main_config() {
    write_main_config_path=$1
    write_main_tmp=${TMPDIR:-/tmp}/sshd_config.$$.tmp

    backup_file "$write_main_config_path"

    awk '
        /^[[:space:]]*Match[[:space:]]/ {
            if (!done) {
                print "PermitRootLogin no"
                done=1
            }
            saw_match=1
            print
            next
        }
        !saw_match && /^[[:space:]]*PermitRootLogin[[:space:]]/ {
            if (!done) {
                print "PermitRootLogin no"
                done=1
            }
            next
        }
        { print }
        END {
            if (!done) {
                print "PermitRootLogin no"
            }
        }
    ' "$write_main_config_path" > "$write_main_tmp"

    cat "$write_main_tmp" > "$write_main_config_path"
    rm -f -- "$write_main_tmp"
    chmod 600 "$write_main_config_path" 2> /dev/null || chmod 644 "$write_main_config_path" || true
    log "Updated SSH main config: $write_main_config_path"
}

#
# Disable SSH root login and reload sshd when possible.
#
harden_sshd_config() {
    harden_sshd_config_path=

    for harden_candidate in /etc/ssh/sshd_config /etc/openssh/sshd_config; do
        if [ -f "$harden_candidate" ]; then
            harden_sshd_config_path=$harden_candidate
            break
        fi
    done

    if [ -z "$harden_sshd_config_path" ]; then
        warn "sshd_config not found; skipping SSH hardening."
        return
    fi

    if sshd_config_includes_dropins "$harden_sshd_config_path"; then
        write_sshd_dropin "$harden_sshd_config_path"
    else
        write_sshd_main_config "$harden_sshd_config_path"
    fi

    if command_exists sshd; then
        if sshd -t > /dev/null 2>&1; then
            log "sshd configuration test passed."
        else
            fail "sshd configuration test failed; review SSH config before restarting sshd."
        fi
    else
        warn "sshd binary not found; could not validate SSH configuration."
    fi

    if command_exists systemctl; then
        if systemctl reload sshd > /dev/null 2>&1; then
            log "Reloaded sshd via systemctl reload sshd."
            return
        elif systemctl reload ssh > /dev/null 2>&1; then
            log "Reloaded ssh via systemctl reload ssh."
            return
        fi
    fi

    if command_exists service; then
        if service sshd reload > /dev/null 2>&1; then
            log "Reloaded sshd via service sshd reload."
            return
        elif service ssh reload > /dev/null 2>&1; then
            log "Reloaded ssh via service ssh reload."
            return
        fi
    fi

    warn "Could not reload sshd automatically. Reload it manually."
}

main() {
    need_root

    log "Starting root account lockdown..."

    lock_root_password
    remove_root_ssh_keys
    harden_sshd_config

    log "Root lockdown complete."
}

main "$@"
