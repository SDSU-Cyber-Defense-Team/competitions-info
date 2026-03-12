#!/usr/bin/env sh
set -eu

USERNAME="failsafe"
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHyCCjfumlggIzuvOa19pD5v5J61Axs7YUnYUThcZgt alex@Calyx-V3'
USER_SHELL="/bin/bash"

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

get_home_dir() {
    awk -F: -v u="$1" '$1 == u {print $6}' /etc/passwd
}

user_exists() {
    id "$1" >/dev/null 2>&1
}

create_user() {
    if user_exists "$USERNAME"; then
        log "User $USERNAME already exists."
        return
    fi

    if command_exists useradd; then
        # -m create home, -s login shell
        useradd -m -s "$USER_SHELL" "$USERNAME"
    elif command_exists adduser; then
        # BusyBox/Debian variants differ, so try a few common forms
        if adduser -D -s "$USER_SHELL" "$USERNAME" 2>/dev/null; then
            :
        elif adduser --disabled-password --gecos "" --shell "$USER_SHELL" "$USERNAME" 2>/dev/null; then
            :
        else
            fail "Could not create user with adduser."
        fi
    else
        fail "Neither useradd nor adduser is available."
    fi

    log "Created user $USERNAME."
}

grant_sudo_access() {
    if command_exists sudo; then
        if [ -d /etc/sudoers.d ]; then
            umask 022
            cat >/etc/sudoers.d/90-"$USERNAME" <<EOF
$USERNAME ALL=(ALL) NOPASSWD: ALL
EOF
            chmod 0440 /etc/sudoers.d/90-"$USERNAME"

            if command_exists visudo; then
                visudo -cf /etc/sudoers.d/90-"$USERNAME" >/dev/null ||
                    fail "sudoers validation failed"
            fi

            log "Configured sudo via /etc/sudoers.d/90-$USERNAME"
            return
        fi
    fi

    # Fallback: distro-specific admin groups
    if command_exists usermod; then
        if getent group sudo >/dev/null 2>&1; then
            usermod -aG sudo "$USERNAME"
            log "Added $USERNAME to sudo group."
            return
        elif getent group wheel >/dev/null 2>&1; then
            usermod -aG wheel "$USERNAME"
            log "Added $USERNAME to wheel group."
            return
        fi
    fi

    warn "Could not configure sudo automatically."
    warn "sudo may not be installed, or no recognized admin method was found."
}

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
        printf '%s\n' "$PUBKEY" >>"$AUTH_KEYS"
        log "Added public key to $AUTH_KEYS"
    else
        log "Public key already present in $AUTH_KEYS"
    fi

    chown -R "$USERNAME":"$USERNAME" "$SSH_DIR"
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

    log "Done."
    log "User: $USERNAME"
    log "SSH key installed for public-key authentication."
}

main "$@"
