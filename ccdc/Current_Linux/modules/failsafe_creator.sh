#!/usr/bin/env sh
set -eu

USERNAME="failsafe"
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHyCCjfumlggIzuvOa19pD5v5J61Axs7YUnYUThcZgt alex@Calyx-V3'
USER_SHELL=

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
# Choose a usable login shell for the failsafe account.
#
select_user_shell() {
    if [ -n "$USER_SHELL" ]; then
        [ -x "$USER_SHELL" ] || fail "Configured shell is not executable: $USER_SHELL"
        return
    fi

    for shell_candidate in /bin/bash /usr/bin/bash /bin/sh /usr/bin/sh; do
        if [ -x "$shell_candidate" ]; then
            USER_SHELL=$shell_candidate
            log "Using login shell for $USERNAME: $USER_SHELL"
            return
        fi
    done

    fail "Could not find a usable login shell for $USERNAME."
}

#
# Look up the configured home directory for a local user.
#
get_home_dir() {
    awk -F: -v u="$1" '$1 == u {print $6}' /etc/passwd
}

user_exists() {
    id "$1" > /dev/null 2>&1
}

#
# Ensure an existing failsafe account has the selected login shell.
#
ensure_user_shell() {
    if command_exists usermod; then
        if usermod -s "$USER_SHELL" "$USERNAME" > /dev/null 2>&1; then
            log "Set $USERNAME login shell to $USER_SHELL."
            return
        fi
    fi

    warn "Could not update login shell for $USERNAME."
}

#
# Clear account expiration when the platform supports chage.
#
ensure_account_not_expired() {
    if command_exists chage; then
        if chage -E -1 "$USERNAME" > /dev/null 2>&1; then
            log "Ensured $USERNAME account is not expired."
            return
        fi
    fi

    warn "Could not verify or clear account expiration for $USERNAME."
}

#
# Create or normalize the failsafe local user account.
#
create_user() {
    select_user_shell

    if user_exists "$USERNAME"; then
        log "User $USERNAME already exists."
        ensure_user_shell
        ensure_account_not_expired
        return
    fi

    if command_exists useradd; then
        # -m create home, -s login shell
        useradd -m -s "$USER_SHELL" "$USERNAME"
    elif command_exists adduser; then
        # BusyBox/Debian variants differ, so try a few common forms
        if adduser -D -s "$USER_SHELL" "$USERNAME" 2> /dev/null; then
            :
        elif adduser --disabled-password --gecos "" --shell "$USER_SHELL" "$USERNAME" 2> /dev/null; then
            :
        else
            fail "Could not create user with adduser."
        fi
    else
        fail "Neither useradd nor adduser is available."
    fi

    log "Created user $USERNAME."
    ensure_account_not_expired
}

#
# Validate the effective sudoers configuration when visudo exists.
#
validate_sudoers() {
    if command_exists visudo; then
        visudo -c > /dev/null || fail "sudoers validation failed"
    fi
}

#
# Validate a candidate sudoers file before installing it.
#
validate_sudoers_file() {
    sudoers_file=$1

    if command_exists visudo; then
        visudo -cf "$sudoers_file" > /dev/null || fail "sudoers validation failed for $sudoers_file"
    fi
}

#
# Return true when /etc/sudoers includes /etc/sudoers.d.
#
sudoers_includes_dropins() {
    [ -r /etc/sudoers ] || return 1

    awk '
        /^[[:space:]]*(#includedir|@includedir)[[:space:]]+\/etc\/sudoers\.d([[:space:]]|$)/ {
            found=1
        }
        END { exit(found ? 0 : 1) }
    ' /etc/sudoers
}

#
# Install a sudoers drop-in for passwordless failsafe sudo.
#
write_sudoers_dropin() {
    [ -d /etc/sudoers.d ] || mkdir -p /etc/sudoers.d

    umask 022
    sudoers_dropin=/etc/sudoers.d/90-"$USERNAME"
    sudoers_dropin_tmp=${TMPDIR:-/tmp}/sudoers-dropin.$$.tmp

    cat > "$sudoers_dropin_tmp" << EOF
Defaults:$USERNAME !requiretty
$USERNAME ALL=(ALL) NOPASSWD: ALL
EOF
    validate_sudoers_file "$sudoers_dropin_tmp"
    cat "$sudoers_dropin_tmp" > "$sudoers_dropin"
    rm -f -- "$sudoers_dropin_tmp"
    chmod 0440 "$sudoers_dropin"
    validate_sudoers
    log "Configured sudo via /etc/sudoers.d/90-$USERNAME"
}

#
# Add a managed failsafe sudo rule directly to /etc/sudoers.
#
write_sudoers_main_config() {
    [ -f /etc/sudoers ] || fail "/etc/sudoers not found; cannot configure sudo."
    backup_file /etc/sudoers

    sudoers_tmp=${TMPDIR:-/tmp}/sudoers.$$.tmp
    awk -v user="$USERNAME" '
        BEGIN {
            start = "# BEGIN CCDC failsafe admin"
            end = "# END CCDC failsafe admin"
        }
        $0 == start { skip=1; next }
        $0 == end { skip=0; next }
        !skip { print }
        END {
            print start
            print "Defaults:" user " !requiretty"
            print user " ALL=(ALL) NOPASSWD: ALL"
            print end
        }
    ' /etc/sudoers > "$sudoers_tmp"

    validate_sudoers_file "$sudoers_tmp"
    cat "$sudoers_tmp" > /etc/sudoers
    rm -f -- "$sudoers_tmp"
    chmod 0440 /etc/sudoers
    validate_sudoers
    log "Configured sudo via managed block in /etc/sudoers."
}

#
# Configure a direct sudo rule using the safest available location.
#
configure_direct_sudo_rule() {
    if command_exists sudo; then
        if [ -d /etc/sudoers.d ] && sudoers_includes_dropins; then
            write_sudoers_dropin
            return
        fi

        write_sudoers_main_config
        return
    fi

    fail "sudo is not installed; cannot configure admin access for $USERNAME."
}

#
# Grant and verify non-interactive sudo access for failsafe.
#
grant_sudo_access() {
    configure_direct_sudo_rule

    if verify_admin_access; then
        return
    fi

    warn "Direct sudo rule did not grant effective admin access; trying admin groups."

    if command_exists usermod; then
        if command_exists getent && getent group sudo > /dev/null 2>&1; then
            usermod -aG sudo "$USERNAME"
            log "Added $USERNAME to sudo group."
        elif command_exists getent && getent group wheel > /dev/null 2>&1; then
            usermod -aG wheel "$USERNAME"
            log "Added $USERNAME to wheel group."
        fi
    fi

    verify_admin_access || fail "Could not verify sudo/admin access for $USERNAME."
}

#
# Install the team SSH public key into failsafe authorized_keys.
#
add_ssh_key() {
    HOME_DIR="$(get_home_dir "$USERNAME")"
    [ -n "$HOME_DIR" ] || fail "Could not determine home directory for $USERNAME"

    SSH_DIR="$HOME_DIR/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    touch "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"

    if ! grep -Fqx "$PUBKEY" "$AUTH_KEYS"; then
        printf '%s\n' "$PUBKEY" >> "$AUTH_KEYS"
        log "Added public key to $AUTH_KEYS"
    else
        log "Public key already present in $AUTH_KEYS"
    fi

    chown -R "$USERNAME":"$USERNAME" "$SSH_DIR"
}

#
# Confirm failsafe has usable non-interactive admin privileges.
#
verify_admin_access() {
    command_exists sudo || return 1

    if command_exists su; then
        if su - "$USERNAME" -c 'sudo -n id -u' 2> /dev/null | grep -qx 0; then
            log "Verified $USERNAME can run sudo non-interactively."
            return 0
        fi
    fi

    if sudo -n -l -U "$USERNAME" > /dev/null 2>&1; then
        log "Verified sudo policy is available for $USERNAME."
        return 0
    fi

    return 1
}

main() {
    need_root

    case "$PUBKEY" in
        ssh-rsa\ * | ssh-ed25519\ * | ecdsa-*\ *) ;;
        *)
            fail "PUBKEY does not look like a valid SSH public key."
            ;;
    esac

    create_user
    grant_sudo_access
    add_ssh_key
    verify_admin_access || fail "Final admin verification failed for $USERNAME."

    log "Done."
    log "User: $USERNAME"
    log "SSH key installed for public-key authentication."
}

main "$@"
