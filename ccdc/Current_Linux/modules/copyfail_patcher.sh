#!/usr/bin/env sh
set -eu

MODPROBE_BLOCK_FILE=/etc/modprobe.d/99-copyfail-disable-algif-aead.conf
COPYFAIL_STRICT=0
COPYFAIL_STATUS=0

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

usage() {
    usage_status=${1:-1}
    cat >&2 << EOF
Usage: ${0##*/} [options]

Options:
  -s, --strict      return failure if residual risk remains
  -h, --help        show this help
EOF
    exit "$usage_status"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -s | --strict)
                COPYFAIL_STRICT=1
                ;;
            -h | --help)
                usage 0
                ;;
            *)
                fail "Unknown option: $1"
                ;;
        esac

        shift
    done
}

module_loaded() {
    [ -r /proc/modules ] || return 1
    awk '$1 == "algif_aead" { found=1 } END { exit(found ? 0 : 1) }' /proc/modules
}

module_visible() {
    [ -d /sys/module/algif_aead ]
}

#
# Try common live-patching clients when they are already installed.
# These commands are intentionally best-effort: enabling live patching usually
# requires a preconfigured token/subscription and distro-specific patch packages.
#
try_livepatch_tools() {
    tried_livepatch=0

    if command_exists canonical-livepatch; then
        tried_livepatch=1
        log "Checking Canonical Livepatch status."
        canonical-livepatch status > /dev/null 2>&1 || true
        canonical-livepatch refresh > /dev/null 2>&1 || true
    fi

    if command_exists kpatch; then
        tried_livepatch=1
        log "Checking kpatch status."
        kpatch list > /dev/null 2>&1 || true
    fi

    if command_exists ksplice; then
        tried_livepatch=1
        log "Checking Ksplice status."
        ksplice all show > /dev/null 2>&1 || true
        ksplice all upgrade -y > /dev/null 2>&1 || true
    fi

    if command_exists kgraft; then
        tried_livepatch=1
        log "Checking kGraft status."
        kgraft status > /dev/null 2>&1 || true
    fi

    if [ "$tried_livepatch" -eq 0 ]; then
        warn "No known live-patching client found."
    fi
}

#
# Prevent future algif_aead module loads. This is the portable no-reboot
# mitigation recommended when the vulnerable code is a loadable module.
#
write_modprobe_block() {
    block_dir=$(dirname "$MODPROBE_BLOCK_FILE")

    mkdir -p "$block_dir"

    if [ -f "$MODPROBE_BLOCK_FILE" ]; then
        backup_file "$MODPROBE_BLOCK_FILE"
    fi

    {
        printf '%s\n' '# Managed by CCDC Copyfail mitigation'
        printf '%s\n' '# Blocks the AF_ALG AEAD interface used by CVE-2026-31431.'
        printf '%s\n' 'blacklist algif_aead'
        printf '%s\n' 'install algif_aead /bin/false'
    } > "$MODPROBE_BLOCK_FILE"

    chmod 644 "$MODPROBE_BLOCK_FILE" 2> /dev/null || true
    log "Wrote module-load block: $MODPROBE_BLOCK_FILE"
}

#
# Attempt to remove algif_aead from the running kernel without rebooting.
#
unload_algif_aead() {
    if ! module_loaded; then
        log "algif_aead is not currently loaded."
        return 0
    fi

    if command_exists modprobe; then
        if modprobe -r algif_aead > /dev/null 2>&1; then
            log "Unloaded algif_aead with modprobe -r."
            return 0
        fi
    fi

    if command_exists rmmod; then
        if rmmod algif_aead > /dev/null 2>&1; then
            log "Unloaded algif_aead with rmmod."
            return 0
        fi
    fi

    warn "Could not unload algif_aead from the running kernel."
    COPYFAIL_STATUS=1
    return 1
}

report_status() {
    if module_loaded; then
        warn "algif_aead is still loaded; Copyfail may remain exploitable until the module is unused, live-patched, or the host is rebooted."
        COPYFAIL_STATUS=1
    elif module_visible; then
        warn "algif_aead is built into or still visible in the running kernel; modprobe blocking will not remove built-in code until boot-time mitigation or kernel replacement."
        COPYFAIL_STATUS=1
    else
        log "algif_aead is not active in the running kernel."
    fi

    if [ "$COPYFAIL_STATUS" -eq 0 ]; then
        log "Copyfail no-reboot mitigation complete."
    else
        warn "Copyfail no-reboot mitigation applied with residual risk."
        warn "Rerun with --strict to make residual risk fail this script."
    fi
}

main() {
    parse_args "$@"
    need_root

    log "Starting Copyfail no-reboot mitigation..."

    try_livepatch_tools
    write_modprobe_block
    unload_algif_aead || true
    report_status

    if [ "$COPYFAIL_STRICT" = "1" ]; then
        exit "$COPYFAIL_STATUS"
    fi

    exit 0
}

main "$@"
