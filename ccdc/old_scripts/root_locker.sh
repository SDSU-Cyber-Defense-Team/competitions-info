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
    command -v "$1" >/dev/null 2>&1
}

backup_file() {
    backup_file_path=$1
    backup_ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo backup)
    cp -p -- "$backup_file_path" "$backup_file_path.bak.$backup_ts"
}

lock_root_password() {
    if command_exists passwd; then
        if passwd -l root >/dev/null 2>&1; then
            log "Locked root password with passwd -l."
            return
        fi
    fi

    if command_exists usermod; then
        if usermod -L root >/dev/null 2>&1; then
            log "Locked root password with usermod -L."
            return
        fi
    fi

    warn "Could not lock root password automatically."
}

remove_root_ssh_keys() {
    remove_ssh_dir=/root/.ssh
    remove_auth_keys=$remove_ssh_dir/authorized_keys

    if [ -f "$remove_auth_keys" ]; then
        backup_file "$remove_auth_keys"
        : >"$remove_auth_keys"
        chmod 600 "$remove_auth_keys" || true
        log "Cleared root authorized_keys."
    else
        log "No root authorized_keys file found."
    fi
}

harden_sshd_config() {
    harden_sshd_config_path=
    harden_ddir=
    harden_dropin=

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

    harden_ddir=$(dirname "$harden_sshd_config_path")/sshd_config.d
    harden_dropin=$harden_ddir/99-disable-root-login.conf

    mkdir -p "$harden_ddir"

    cat >"$harden_dropin" <<'EOF'
# Managed by root lockdown script
PermitRootLogin no
EOF

    chmod 644 "$harden_dropin"
    log "Wrote SSH drop-in: $harden_dropin"

    if command_exists sshd; then
        if sshd -t >/dev/null 2>&1; then
            log "sshd configuration test passed."
        else
            fail "sshd configuration test failed; review SSH config before restarting sshd."
        fi
    else
        warn "sshd binary not found; could not validate SSH configuration."
    fi

    if command_exists systemctl; then
        if systemctl reload sshd >/dev/null 2>&1; then
            log "Reloaded sshd via systemctl reload sshd."
            return
        elif systemctl reload ssh >/dev/null 2>&1; then
            log "Reloaded ssh via systemctl reload ssh."
            return
        fi
    fi

    if command_exists service; then
        if service sshd reload >/dev/null 2>&1; then
            log "Reloaded sshd via service sshd reload."
            return
        elif service ssh reload >/dev/null 2>&1; then
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
