#!/usr/bin/env sh
set -eu

COORDINATE_REPO_URL=${COORDINATE_REPO_URL:-https://git.sr.ht/~sourque/coordinate}
CCDC_REPO_URL=${CCDC_REPO_URL:-https://github.com/SocomX1/CCDC-Resources.git}
CCDC_DIR=${CCDC_DIR:-$HOME/CCDC-Resources}
CACHE_DIR=${CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/ccdc-minute-zero}
SKIP_PACKAGE_INSTALL=${SKIP_PACKAGE_INSTALL:-0}
PROFILE_SNIPPET=${PROFILE_SNIPPET:-$HOME/.profile}

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

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

#
# Choose a binary install directory that should work immediately.
#
default_bin_dir() {
    if [ "${BIN_DIR:-}" ]; then
        printf '%s\n' "$BIN_DIR"
        return
    fi

    if [ "$(id -u)" -eq 0 ] || command_exists sudo; then
        printf '%s\n' /usr/local/bin
    else
        printf '%s\n' "$HOME/.local/bin"
    fi
}

need_command() {
    command_exists "$1" || fail "Required command not found: $1"
}

#
# Run a command as root using sudo when needed.
#
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command_exists sudo; then
        sudo "$@"
    else
        fail "Need root privileges to run: $*"
    fi
}

#
# Install missing dependencies needed to clone and build Coordinate.
#
install_packages() {
    [ "$SKIP_PACKAGE_INSTALL" = "0" ] || return 0

    missing_git=0
    missing_go=0
    command_exists git || missing_git=1
    if ! command_exists coordinate && ! command_exists go; then
        missing_go=1
    fi

    [ "$missing_git" -eq 1 ] || [ "$missing_go" -eq 1 ] || return 0

    log "Installing missing build dependencies."

    if command_exists apt-get; then
        packages="ca-certificates"
        [ "$missing_git" -eq 1 ] && packages="$packages git"
        [ "$missing_go" -eq 1 ] && packages="$packages golang-go"
        run_as_root apt-get update
        run_as_root apt-get install -y $packages
    elif command_exists dnf; then
        packages="ca-certificates"
        [ "$missing_git" -eq 1 ] && packages="$packages git"
        [ "$missing_go" -eq 1 ] && packages="$packages golang"
        run_as_root dnf install -y $packages
    elif command_exists yum; then
        packages="ca-certificates"
        [ "$missing_git" -eq 1 ] && packages="$packages git"
        [ "$missing_go" -eq 1 ] && packages="$packages golang"
        run_as_root yum install -y $packages
    elif command_exists pacman; then
        packages="ca-certificates"
        [ "$missing_git" -eq 1 ] && packages="$packages git"
        [ "$missing_go" -eq 1 ] && packages="$packages go"
        run_as_root pacman -Sy --needed --noconfirm $packages
    elif command_exists apk; then
        packages="ca-certificates"
        [ "$missing_git" -eq 1 ] && packages="$packages git"
        [ "$missing_go" -eq 1 ] && packages="$packages go"
        run_as_root apk add $packages
    else
        fail "No supported package manager found. Install git and Go, then rerun."
    fi
}

#
# Clone a repository or fast-forward an existing clean checkout.
#
clone_or_update() {
    repo_url=$1
    dest_dir=$2

    if [ -d "$dest_dir/.git" ]; then
        if [ -n "$(git -C "$dest_dir" status --porcelain)" ]; then
            warn "Existing repo has local changes; skipping update: $dest_dir"
            return 0
        fi

        log "Updating existing repo: $dest_dir"
        git -C "$dest_dir" pull --ff-only
        return 0
    fi

    if [ -e "$dest_dir" ]; then
        fail "Destination exists but is not a git repo: $dest_dir"
    fi

    log "Cloning $repo_url to $dest_dir"
    git clone "$repo_url" "$dest_dir"
}

#
# Build and install the Coordinate binary if it is not available.
#
install_coordinate() {
    BIN_DIR=$(default_bin_dir)
    mkdir -p "$CACHE_DIR"

    if [ -d "$BIN_DIR" ]; then
        :
    elif [ "$(id -u)" -eq 0 ]; then
        mkdir -p "$BIN_DIR"
    elif [ "$BIN_DIR" = /usr/local/bin ] || [ "${BIN_DIR#/usr/}" != "$BIN_DIR" ]; then
        run_as_root mkdir -p "$BIN_DIR"
    else
        mkdir -p "$BIN_DIR"
    fi

    if command_exists coordinate; then
        log "Coordinate already available: $(command -v coordinate)"
        return 0
    fi

    coordinate_src=$CACHE_DIR/coordinate
    clone_or_update "$COORDINATE_REPO_URL" "$coordinate_src"

    need_command go

    log "Building Coordinate into $BIN_DIR/coordinate"
    git -C "$coordinate_src" status --short > /dev/null
    build_output=$CACHE_DIR/coordinate.bin
    (cd "$coordinate_src" && go build -o "$build_output" .)

    if [ -w "$BIN_DIR" ]; then
        cp "$build_output" "$BIN_DIR/coordinate"
        chmod 755 "$BIN_DIR/coordinate"
    else
        run_as_root cp "$build_output" "$BIN_DIR/coordinate"
        run_as_root chmod 755 "$BIN_DIR/coordinate"
    fi
}

#
# Return true when the current PATH already contains a directory.
#
path_contains_dir() {
    check_dir=$1

    case ":$PATH:" in
        *":$check_dir:"*) return 0 ;;
        *) return 1 ;;
    esac
}

#
# Link Coordinate into ~/bin when that directory is already on PATH.
#
install_path_fallback() {
    user_bin=$HOME/bin

    [ "$BIN_DIR" != "$user_bin" ] || return 0
    [ -x "$BIN_DIR/coordinate" ] || return 0
    path_contains_dir "$user_bin" || return 0

    mkdir -p "$user_bin"
    if command_exists ln; then
        ln -sf "$BIN_DIR/coordinate" "$user_bin/coordinate"
        log "Linked Coordinate into PATH fallback: $user_bin/coordinate"
    fi
}

#
# Persist the local binary path for future shells when needed.
#
configure_path_profile() {
    BIN_DIR=$(default_bin_dir)
    path_line='export PATH="$HOME/.local/bin:$PATH"'

    path_contains_dir "$BIN_DIR" && return 0
    [ "$BIN_DIR" = "$HOME/.local/bin" ] || return 0

    if [ -f "$PROFILE_SNIPPET" ] && grep -Fqx "$path_line" "$PROFILE_SNIPPET"; then
        return 0
    fi

    {
        printf '\n'
        printf '# Added by CCDC minute-zero setup for Coordinate.\n'
        printf '%s\n' "$path_line"
    } >> "$PROFILE_SNIPPET"

    log "Added $BIN_DIR to PATH in $PROFILE_SNIPPET for future shells."
}

#
# Print the next operator commands after setup completes.
#
print_next_steps() {
    BIN_DIR=$(default_bin_dir)

    cat << EOF

[+] Setup complete. Hardening scripts are ready for remote deployment via Coordinate.

Coordinate:
  $BIN_DIR/coordinate

CCDC resources:
  $CCDC_DIR

If coordinate is not found in this terminal, run:
  export PATH="$BIN_DIR:\$PATH"

Next:
  cd "$CCDC_DIR"
  edit deploy/allowlist.txt
  coordinate -y -t TARGETS -u root -p 'DEFAULT_ROOT_PASSWORD' -T 90 deploy/coordinate_deploy.sh
EOF
}

main() {
    install_packages
    need_command git

    install_coordinate
    install_path_fallback
    configure_path_profile
    clone_or_update "$CCDC_REPO_URL" "$CCDC_DIR"
    print_next_steps
}

main "$@"
