#!/usr/bin/env sh
set -eu

ADMIN_ACCOUNT_USERNAME="failsafe"
ASSUME_YES=0
DRY_RUN=0
EXCLUDE_USERS=
LOCK_FAILURES=0

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
Usage: ${0##*/} [options] <authorized_user_list>

Options:
  -y, --yes                 run without interactive review or confirmation
  -n, --dry-run             print target accounts without changing the system
      --exclude USERS       comma-separated usernames to exclude from lockdown
      --admin USERNAME      admin account to always exclude (default: failsafe)
  -h, --help                show this help
EOF
    exit "$usage_status"
}

cleanup() {
    [ -n "${TMPDIR_PATH:-}" ] && [ -d "$TMPDIR_PATH" ] && rm -rf -- "$TMPDIR_PATH"
}

#
# Determine the minimum normal-user UID for the local system.
#
get_uid_min() {
    uid_min=1000

    if [ -r /etc/login.defs ]; then
        found_uid_min=$(
            awk '
                /^[[:space:]]*UID_MIN[[:space:]]+[0-9]+/ {
                    print $2
                    exit
                }
            ' /etc/login.defs 2> /dev/null || true
        )
        if [ -n "$found_uid_min" ]; then
            uid_min=$found_uid_min
        fi
    fi

    printf '%s\n' "$uid_min"
}

#
# Normalize the allowlist by trimming whitespace and ignoring comments.
#
normalize_allowlist() {
    input_file=$1
    output_file=$2

    awk '
        {
            gsub(/\r/, "", $0)
            sub(/^[[:space:]]+/, "", $0)
            sub(/[[:space:]]+$/, "", $0)
            if ($0 == "" || $0 ~ /^#/) next
            print $0
        }
    ' "$input_file" | sort -u > "$output_file"
}

#
# Return true when a shell appears to permit interactive login.
#
is_shell_interactive() {
    user_shell=$1

    case "$user_shell" in
        "" | *"/nologin" | *"/false")
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

user_in_allowlist() {
    username=$1
    allowlist_file=$2

    grep -Fqx -- "$username" "$allowlist_file"
}

#
# Lock a local account using the available account management tool.
#
lock_account() {
    username=$1

    if command_exists passwd; then
        if passwd -l "$username" > /dev/null 2>&1; then
            log "Locked account: $username"
            return 0
        fi
    fi

    if command_exists usermod; then
        if usermod -L "$username" > /dev/null 2>&1; then
            log "Locked account: $username"
            return 0
        fi
    fi

    warn "Could not lock account with passwd/usermod: $username"
    return 1
}

clear_supplementary_groups_usermod() {
    username=$1
    usermod -G "" "$username" > /dev/null 2>&1
}

#
# Remove group memberships without relying on usermod -G.
#
clear_supplementary_groups_fallback() {
    username=${1:?missing username}

    while IFS=: read -r group_name _ _ members; do
        [ -n "$group_name" ] || continue
        [ -n "$members" ] || continue

        case ",$members," in
            *",$username,"*)
                if command_exists gpasswd; then
                    if gpasswd -d "$username" "$group_name" > /dev/null 2>&1; then
                        :
                    else
                        warn "Could not remove $username from group $group_name with gpasswd"
                    fi
                elif command_exists deluser; then
                    if deluser "$username" "$group_name" > /dev/null 2>&1; then
                        :
                    else
                        warn "Could not remove $username from group $group_name with deluser"
                    fi
                else
                    warn "No supported tool found to remove $username from group $group_name"
                fi
                ;;
        esac
    done < /etc/group

    return 0
}

#
# Clear supplementary groups using the best available method.
#
clear_supplementary_groups() {
    username=$1

    if command_exists usermod; then
        if clear_supplementary_groups_usermod "$username"; then
            log "Cleared supplementary groups for: $username"
            return 0
        fi
    fi

    clear_supplementary_groups_fallback "$username"
    log "Attempted to clear supplementary groups for: $username"
}

#
# Back up and remove SSH authorized key files for a user.
#
remove_authorized_keys() {
    username=$1
    user_home=$2

    [ -n "$user_home" ] || return 0
    [ "$user_home" != "/" ] || return 0

    ssh_dir=$user_home/.ssh
    removed_any=0

    if [ -f "$ssh_dir/authorized_keys" ]; then
        backup_file "$ssh_dir/authorized_keys"
        rm -f -- "$ssh_dir/authorized_keys"
        removed_any=1
    fi

    if [ -f "$ssh_dir/authorized_keys2" ]; then
        backup_file "$ssh_dir/authorized_keys2"
        rm -f -- "$ssh_dir/authorized_keys2"
        removed_any=1
    fi

    if [ "$removed_any" -eq 1 ]; then
        log "Removed authorized_keys for: $username"
    fi
}

print_target_list() {
    list_file=$1
    header_text=$2

    printf '\n%s\n' "$header_text"
    while IFS=: read -r username uid home shell; do
        printf '  - %s (uid=%s, home=%s, shell=%s)\n' "$username" "$uid" "$home" "$shell"
    done < "$list_file"
}

#
# Return true when a target list contains the specified username.
#
target_file_contains_user() {
    username=$1
    list_file=$2

    awk -F: -v u="$username" '$1 == u { found=1; exit } END { exit(found ? 0 : 1) }' "$list_file"
}

remove_user_from_target_file() {
    username=$1
    input_file=$2
    output_file=$3

    awk -F: -v u="$username" '$1 != u' "$input_file" > "$output_file"
}

#
# Apply non-interactive exclusions to the computed target list.
#
apply_excludes() {
    input_file=$1
    output_file=$2

    cp -- "$input_file" "$output_file"
    [ -n "$EXCLUDE_USERS" ] || return 0

    old_ifs=$IFS
    IFS=,
    for exclude_user in $EXCLUDE_USERS; do
        IFS=$old_ifs
        [ -n "$exclude_user" ] || continue

        if target_file_contains_user "$exclude_user" "$output_file"; then
            remove_user_from_target_file "$exclude_user" "$output_file" "$output_file.tmp"
            mv -- "$output_file.tmp" "$output_file"
            log "Excluded account from lockdown: $exclude_user"
        else
            warn "Configured exclude user was not in target list: $exclude_user"
        fi

        IFS=,
    done
    IFS=$old_ifs
}

#
# Let an operator interactively remove accounts from the target list.
#
review_targets() {
    input_file=$1
    output_file=$2

    cp -- "$input_file" "$output_file"

    while :; do
        print_target_list "$output_file" "Current accounts marked for lockdown:"

        printf '\nEnter username(s) to EXCLUDE from lockdown, separated by spaces.\n'
        printf 'Usernames must match exactly as shown above.\n'
        printf 'Press Enter to keep this list unchanged: '
        IFS= read -r exclude_line || fail "Could not read exclusion input"

        [ -n "$exclude_line" ] || break

        new_file=$output_file.new
        cp -- "$output_file" "$new_file"

        invalid=0

        for exclude_user in $exclude_line; do
            if grep -Fqx -- "$exclude_user" "$EXCLUDED_SEEN_FILE" 2> /dev/null; then
                warn "Username already excluded earlier: $exclude_user"
                continue
            fi

            if target_file_contains_user "$exclude_user" "$new_file"; then
                remove_user_from_target_file "$exclude_user" "$new_file" "$new_file.tmp"
                mv -- "$new_file.tmp" "$new_file"
                printf '%s\n' "$exclude_user" >> "$EXCLUDED_SEEN_FILE"
                log "Excluded account from lockdown: $exclude_user"
            else
                warn "Username not found exactly in current target list: $exclude_user"
                invalid=1
            fi
        done

        mv -- "$new_file" "$output_file"

        if [ ! -s "$output_file" ]; then
            : > "$output_file"
            warn "All accounts were excluded. Nothing remains to lock down."
            return 1
        fi

        print_target_list "$output_file" "Reviewed accounts that WILL remain targeted:"

        if [ "$invalid" -ne 0 ]; then
            warn "One or more entered usernames were invalid and were not excluded."
        fi

        printf '\nExclude more accounts? [y/N]: '
        IFS= read -r answer || fail "Could not read answer"
        case $answer in
            y | Y | yes | YES) ;;
            *) break ;;
        esac
    done
}

#
# Parse CLI options and validate the supplied allowlist path.
#
parse_args() {
    ALLOWLIST_INPUT=

    while [ "$#" -gt 0 ]; do
        case "$1" in
            -y | --yes)
                ASSUME_YES=1
                shift
                ;;
            -n | --dry-run)
                DRY_RUN=1
                shift
                ;;
            --exclude)
                [ "$#" -ge 2 ] || fail "--exclude requires a comma-separated user list"
                EXCLUDE_USERS=$2
                shift 2
                ;;
            --exclude=*)
                EXCLUDE_USERS=${1#--exclude=}
                shift
                ;;
            --admin)
                [ "$#" -ge 2 ] || fail "--admin requires a username"
                ADMIN_ACCOUNT_USERNAME=$2
                shift 2
                ;;
            --admin=*)
                ADMIN_ACCOUNT_USERNAME=${1#--admin=}
                shift
                ;;
            -h | --help)
                usage 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                fail "Unknown option: $1"
                ;;
            *)
                [ -z "$ALLOWLIST_INPUT" ] || fail "Only one allowlist file may be supplied"
                ALLOWLIST_INPUT=$1
                shift
                ;;
        esac
    done

    while [ "$#" -gt 0 ]; do
        [ -z "$ALLOWLIST_INPUT" ] || fail "Only one allowlist file may be supplied"
        ALLOWLIST_INPUT=$1
        shift
    done

    [ -n "$ALLOWLIST_INPUT" ] || usage

    [ -f "$ALLOWLIST_INPUT" ] || fail "Allowlist file not found: $ALLOWLIST_INPUT"
    [ -r "$ALLOWLIST_INPUT" ] || fail "Allowlist file is not readable: $ALLOWLIST_INPUT"
    [ -r /etc/passwd ] || fail "Cannot read /etc/passwd"
}

#
# Create temporary files used while building and reviewing targets.
#
setup_workspace() {
    TMPDIR_PATH=${TMPDIR:-/tmp}/account-lockdown.$$
    mkdir -p -- "$TMPDIR_PATH" || fail "Could not create temporary directory"
    trap cleanup EXIT HUP INT TERM

    ALLOWLIST_FILE=$TMPDIR_PATH/allowlist.txt
    TARGETS_FILE=$TMPDIR_PATH/targets.txt
    REVIEWED_TARGETS_FILE=$TMPDIR_PATH/reviewed_targets.txt
    EXCLUDED_SEEN_FILE=$TMPDIR_PATH/excluded_seen.txt

    : > "$TARGETS_FILE"
    : > "$EXCLUDED_SEEN_FILE"
}

#
# Normalize the allowlist and load platform UID policy.
#
prepare_allowlist() {
    normalize_allowlist "$ALLOWLIST_INPUT" "$ALLOWLIST_FILE"
    UID_MIN=$(get_uid_min)

    log "Using UID_MIN=$UID_MIN"
    log "Reading authorized account list from: $ALLOWLIST_INPUT"
}

#
# Add a user to the target list when absent from the allowlist.
#
append_target_if_unauthorized() {
    username=$1
    uid=$2
    home=$3
    shell=$4

    if ! user_in_allowlist "$username" "$ALLOWLIST_FILE"; then
        printf '%s:%s:%s:%s\n' "$username" "$uid" "$home" "$shell" >> "$TARGETS_FILE"
    fi
}

#
# Build the list of local login-capable accounts to lock.
#
build_target_list() {
    while IFS=: read -r username _ uid _ _ home shell; do
        [ -n "$username" ] || continue
        [ "$username" = "root" ] && continue
        [ "$username" = "$ADMIN_ACCOUNT_USERNAME" ] && continue

        case "$uid" in
            '' | *[!0-9]*) continue ;;
        esac

        [ "$uid" -ge "$UID_MIN" ] || continue
        is_shell_interactive "$shell" || continue

        append_target_if_unauthorized "$username" "$uid" "$home" "$shell"
    done < /etc/passwd
}

#
# Review targets and require confirmation unless automation is enabled.
#
review_and_confirm_targets() {
    if [ ! -s "$TARGETS_FILE" ]; then
        log "No unauthorized local login-capable accounts found."
        exit 0
    fi

    if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        apply_excludes "$TARGETS_FILE" "$REVIEWED_TARGETS_FILE"
    else
        if ! review_targets "$TARGETS_FILE" "$REVIEWED_TARGETS_FILE"; then
            log "No accounts remain selected for lockdown."
            exit 0
        fi
    fi

    if [ ! -s "$REVIEWED_TARGETS_FILE" ]; then
        log "No accounts remain selected for lockdown."
        exit 0
    fi

    print_target_list "$REVIEWED_TARGETS_FILE" "Final reviewed accounts that WILL be locked down:"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "Dry run requested; no account changes will be made."
        exit 0
    fi

    if [ "$ASSUME_YES" -eq 1 ]; then
        log "Non-interactive confirmation enabled by --yes."
        return
    fi

    printf '\nThis will:\n'
    printf '  * lock each account\n'
    printf '  * remove supplementary groups\n'
    printf '  * delete ~/.ssh/authorized_keys and ~/.ssh/authorized_keys2\n'
    printf '\nType YES to continue: '
    IFS= read -r confirm || fail "Could not read confirmation"

    [ "$confirm" = "YES" ] || fail "Aborted."
}

#
# Back up local account databases before modifying accounts.
#
backup_system_files() {
    backup_file /etc/passwd
    if [ -r /etc/group ]; then
        backup_file /etc/group
    fi
    if [ -r /etc/shadow ]; then
        backup_file /etc/shadow
    fi
}

#
# Lock targeted accounts, clear groups, and remove SSH keys.
#
lockdown_targets() {
    while IFS=: read -r username _ home _; do
        log "Processing account: $username"
        if ! lock_account "$username"; then
            LOCK_FAILURES=$((LOCK_FAILURES + 1))
        fi
        clear_supplementary_groups "$username"
        remove_authorized_keys "$username" "$home"
    done < "$REVIEWED_TARGETS_FILE"

    if [ "$LOCK_FAILURES" -gt 0 ]; then
        fail "$LOCK_FAILURES account(s) could not be locked."
    fi
}

main() {
    parse_args "$@"
    need_root
    setup_workspace
    prepare_allowlist
    build_target_list
    review_and_confirm_targets
    backup_system_files
    lockdown_targets

    log "Account lockdown completed."
}

main "$@"
