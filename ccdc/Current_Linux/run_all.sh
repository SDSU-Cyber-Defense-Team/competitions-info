#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
MODULE_DIR=$SCRIPT_DIR/modules
ALLOWLIST_INPUT=
ADMIN_ACCOUNT_USERNAME=${ADMIN_ACCOUNT_USERNAME:-failsafe}
COPYFAIL_PATCHER_ARGS=
DIRTYFRAG_PATCHER_ARGS=
USER_LOCKER_EXTRA_ARGS=${USER_LOCKER_EXTRA_ARGS:-}

log() {
    printf '[+] %s\n' "$*"
}

fail() {
    printf '[x] %s\n' "$*" >&2
    exit 1
}

need_root() {
    [ "$(id -u)" -eq 0 ] || fail "This script must be run as root."
}

usage() {
    usage_status=${1:-1}
    cat >&2 << EOF
Usage: ${0##*/} [options] <authorized_user_list>

Options:
      --copyfail-strict      return failure if Copyfail residual risk remains
      --dirtyfrag-force      unload DirtyFrag modules even if IPsec or AFS use is detected
      --dirtyfrag-strict     return failure if DirtyFrag residual risk remains
  -h, --help                 show this help
EOF
    exit "$usage_status"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --copyfail-strict)
                COPYFAIL_PATCHER_ARGS="$COPYFAIL_PATCHER_ARGS --strict"
                ;;
            --dirtyfrag-force)
                DIRTYFRAG_PATCHER_ARGS="$DIRTYFRAG_PATCHER_ARGS --force"
                ;;
            --dirtyfrag-strict)
                DIRTYFRAG_PATCHER_ARGS="$DIRTYFRAG_PATCHER_ARGS --strict"
                ;;
            -h | --help)
                usage 0
                ;;
            -*)
                fail "Unknown option: $1"
                ;;
            *)
                [ -z "$ALLOWLIST_INPUT" ] || fail "Unexpected extra argument: $1"
                ALLOWLIST_INPUT=$1
                ;;
        esac

        shift
    done
}

#
# Run a bundled hardening module from the modules directory.
#
run_script() {
    script_name=$1
    shift

    script_path=$MODULE_DIR/$script_name
    [ -f "$script_path" ] || fail "Required script not found: $script_path"

    log "Running $script_name..."
    sh "$script_path" "$@"
}

main() {
    parse_args "$@"
    need_root
    [ -n "$ALLOWLIST_INPUT" ] || usage 1
    [ -f "$ALLOWLIST_INPUT" ] || fail "Allowlist file not found: $ALLOWLIST_INPUT"
    [ -r "$ALLOWLIST_INPUT" ] || fail "Allowlist file is not readable: $ALLOWLIST_INPUT"

    run_script failsafe_creator.sh
    # shellcheck disable=SC2086
    run_script copyfail_patcher.sh $COPYFAIL_PATCHER_ARGS
    # shellcheck disable=SC2086
    run_script dirtyfrag_patcher.sh $DIRTYFRAG_PATCHER_ARGS
    run_script root_locker.sh

    # shellcheck disable=SC2086
    run_script user_locker.sh --yes --admin "$ADMIN_ACCOUNT_USERNAME" $USER_LOCKER_EXTRA_ARGS "$ALLOWLIST_INPUT"

    log "CCDC hardening run complete."
}

main "$@"
