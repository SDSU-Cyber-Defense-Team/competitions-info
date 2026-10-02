#!/usr/bin/env sh
set -eu

MODPROBE_BLOCK_FILE=/etc/modprobe.d/99-dirtyfrag-disable.conf
DIRTYFRAG_FORCE=0
DIRTYFRAG_STRICT=0
DIRTYFRAG_STATUS=0
DIRTYFRAG_IPSEC_ACTIVE=0
DIRTYFRAG_AFS_ACTIVE=0

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
  -f, --force       unload modules even if IPsec or AFS use is detected
  -s, --strict      return failure if residual risk remains
  -h, --help        show this help
EOF
    exit "$usage_status"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -f | --force)
                DIRTYFRAG_FORCE=1
                ;;
            -s | --strict)
                DIRTYFRAG_STRICT=1
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
    module_name=$1

    [ -r /proc/modules ] || return 1
    awk -v module_name="$module_name" '$1 == module_name { found=1 } END { exit(found ? 0 : 1) }' /proc/modules
}

module_visible() {
    module_name=$1

    [ -d "/sys/module/$module_name" ]
}

detect_ipsec_use() {
    if ! command_exists ip; then
        return 1
    fi

    if ip xfrm state 2> /dev/null | awk 'NF { found=1 } END { exit(found ? 0 : 1) }'; then
        return 0
    fi

    if ip xfrm policy 2> /dev/null | awk 'NF { found=1 } END { exit(found ? 0 : 1) }'; then
        return 0
    fi

    return 1
}

detect_afs_use() {
    if [ -d /proc/fs/afs ]; then
        return 0
    fi

    if module_loaded kafs || module_loaded openafs; then
        return 0
    fi

    if command_exists mount; then
        if mount 2> /dev/null | awk '$0 ~ / type (afs|openafs) / { found=1 } END { exit(found ? 0 : 1) }'; then
            return 0
        fi
    fi

    return 1
}

detect_service_impact() {
    if detect_ipsec_use; then
        DIRTYFRAG_IPSEC_ACTIVE=1
        warn "Detected IPsec/XFRM state or policy; unloading esp4/esp6 may disrupt IPsec VPN or tunnel traffic."
    else
        log "No active IPsec/XFRM state or policy detected."
    fi

    if detect_afs_use; then
        DIRTYFRAG_AFS_ACTIVE=1
        warn "Detected possible AFS/RxRPC use; unloading rxrpc may disrupt AFS connectivity."
    else
        log "No AFS/RxRPC service indicators detected."
    fi
}

write_modprobe_block() {
    block_dir=$(dirname "$MODPROBE_BLOCK_FILE")

    mkdir -p "$block_dir"

    if [ -f "$MODPROBE_BLOCK_FILE" ]; then
        backup_file "$MODPROBE_BLOCK_FILE"
    fi

    {
        printf '%s\n' '# Managed by CCDC DirtyFrag mitigation'
        printf '%s\n' '# Blocks ESP and RxRPC modules used by CVE-2026-43284/CVE-2026-43500/CVE-2026-46300.'
        printf '%s\n' 'blacklist esp4'
        printf '%s\n' 'blacklist esp6'
        printf '%s\n' 'blacklist rxrpc'
        printf '%s\n' 'install esp4 /bin/false'
        printf '%s\n' 'install esp6 /bin/false'
        printf '%s\n' 'install rxrpc /bin/false'
    } > "$MODPROBE_BLOCK_FILE"

    chmod 644 "$MODPROBE_BLOCK_FILE" 2> /dev/null || true
    log "Wrote module-load block: $MODPROBE_BLOCK_FILE"
}

should_skip_unload() {
    module_name=$1

    [ "$DIRTYFRAG_FORCE" = "1" ] && return 1

    case "$module_name" in
        esp4 | esp6)
            [ "$DIRTYFRAG_IPSEC_ACTIVE" -eq 1 ] && return 0
            ;;
        rxrpc)
            [ "$DIRTYFRAG_AFS_ACTIVE" -eq 1 ] && return 0
            ;;
    esac

    return 1
}

unload_module() {
    module_name=$1

    if ! module_loaded "$module_name"; then
        log "$module_name is not currently loaded."
        return 0
    fi

    if should_skip_unload "$module_name"; then
        warn "Skipping unload of $module_name to avoid likely service disruption. Rerun with --force to force unloading."
        DIRTYFRAG_STATUS=1
        return 1
    fi

    if command_exists modprobe; then
        if modprobe -r "$module_name" > /dev/null 2>&1; then
            log "Unloaded $module_name with modprobe -r."
            return 0
        fi
    fi

    if command_exists rmmod; then
        if rmmod "$module_name" > /dev/null 2>&1; then
            log "Unloaded $module_name with rmmod."
            return 0
        fi
    fi

    warn "Could not unload $module_name from the running kernel."
    DIRTYFRAG_STATUS=1
    return 1
}

unload_dirtyfrag_modules() {
    unload_module esp4 || true
    unload_module esp6 || true
    unload_module rxrpc || true
}

report_module_status() {
    module_name=$1

    if module_loaded "$module_name"; then
        warn "$module_name is still loaded; DirtyFrag may remain exploitable through this module."
        DIRTYFRAG_STATUS=1
    elif module_visible "$module_name"; then
        warn "$module_name is built into or still visible in the running kernel; modprobe blocking may not fully mitigate it without a kernel update."
        DIRTYFRAG_STATUS=1
    else
        log "$module_name is not active in the running kernel."
    fi
}

report_status() {
    report_module_status esp4
    report_module_status esp6
    report_module_status rxrpc

    if [ "$DIRTYFRAG_STATUS" -eq 0 ]; then
        log "DirtyFrag no-reboot mitigation complete."
    else
        warn "DirtyFrag no-reboot mitigation applied with residual risk."
        warn "Rerun with --strict to make residual risk fail this script."
    fi
}

main() {
    parse_args "$@"
    need_root

    log "Starting DirtyFrag no-reboot mitigation..."

    detect_service_impact
    write_modprobe_block
    unload_dirtyfrag_modules
    report_status

    if [ "$DIRTYFRAG_STRICT" = "1" ]; then
        exit "$DIRTYFRAG_STATUS"
    fi

    exit 0
}

main "$@"
