#!/bin/bash
# setup_nax.sh — Build and deploy NaxDarks Linux extenders to an Adaptix Server directory.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

error_exit()  { echo -e "${RED}✗ $1${NC}"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAX_ROOT="$SCRIPT_DIR"
SERVER_DIR=""
ACTION="all"
GO_BIN=""
GOEXPERIMENT=""
SERVER_GO_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_DIR="$(realpath "$2" 2>/dev/null || echo "$2")"; shift 2 ;;
        --action) ACTION="$2"; shift 2 ;;
        -h|--help) ACTION="help"; shift ;;
        *) error_exit "Unknown parameter: $1\nRun $0 --help for usage." ;;
    esac
done

if [ "$ACTION" = "help" ] || [ -z "$SERVER_DIR" ]; then
    cat <<EOF
Usage: $0 --server <Server_directory> [--action <action>]

Actions:
  all                   Build all 3 plugins + deploy + register (default)
  agent-linux           Build Linux agent plugin only
  listener-linux-tcp    Build Linux TCP listener only
  listener-linux-https  Build Linux HTTPS listener only
  deploy                Deploy configs only (no build)
  prereqs               Check build prerequisites only
EOF
    [ "$ACTION" = "help" ] && exit 0
    exit 1
fi

[ ! -d "$SERVER_DIR" ] && error_exit "Server directory does not exist: $SERVER_DIR"
if [ ! -f "$SERVER_DIR/adaptixserver" ] && [ ! -f "$SERVER_DIR/profile.yaml" ]; then
    error_exit "Not an Adaptix Server directory: $SERVER_DIR"
fi

EXTENDERS_DIR="$SERVER_DIR/extenders"

# ===== PREREQUISITES =====

find_go() {
    [ -n "$GO_BIN" ] && return
    if [ -x /usr/local/go/bin/go ]; then GO_BIN="/usr/local/go/bin/go"
    elif command -v go >/dev/null 2>&1; then GO_BIN="$(command -v go)"
    else error_exit "Go compiler not found. Install from https://go.dev/dl/"; fi
}

check_prereqs() {
    local missing=()
    if [ -x /usr/local/go/bin/go ]; then GO_BIN="/usr/local/go/bin/go"
    elif command -v go >/dev/null 2>&1; then GO_BIN="$(command -v go)"
    else missing+=("go"); fi
    command -v gcc >/dev/null 2>&1 || missing+=("gcc")
    [ ${#missing[@]} -gt 0 ] && error_exit "Missing prerequisites: ${missing[*]}"
}

detect_server_buildinfo() {
    find_go
    local server_bin="$SERVER_DIR/adaptixserver"
    [ ! -f "$server_bin" ] && return
    local buildinfo
    buildinfo=$("$GO_BIN" version -m "$server_bin" 2>/dev/null)
    [ -z "$buildinfo" ] && return
    SERVER_GO_VERSION=$(echo "$buildinfo" | awk 'NR==1 { print $2 }' | sed -E 's/-X:.*$//' | sed -E 's/ X:.*$//')
    GOEXPERIMENT=$(echo "$buildinfo" | awk '$1=="build" && $2 ~ /^GOEXPERIMENT=/ { sub(/^GOEXPERIMENT=/, "", $2); print $2 }')
    if [ -n "$SERVER_GO_VERSION" ]; then
        local local_ver
        local_ver=$("$GO_BIN" version 2>/dev/null | awk '{print $3}')
        [ "$SERVER_GO_VERSION" != "$local_ver" ] && export GOTOOLCHAIN="$SERVER_GO_VERSION"
    fi
}

apply_build_env() {
    [ -n "$SERVER_GO_VERSION" ] && export GOTOOLCHAIN="$SERVER_GO_VERSION"
    [ -n "$GOEXPERIMENT" ]      && export GOEXPERIMENT
}

# ===== BUILD FUNCTIONS =====

build_plugin() {
    local name="$1"
    local make_target="$2"
    local dest="$EXTENDERS_DIR/$name"
    local log_file="/tmp/nax_build_${name}.log"

    mkdir -p "$dest" 2>/dev/null
    apply_build_env

    if make -C "$NAX_ROOT/src_server" "$make_target" \
        SERVER_DIR="$SERVER_DIR" GOEXPERIMENT="$GOEXPERIMENT" \
        GOTOOLCHAIN="$SERVER_GO_VERSION" GO="$GO_BIN" \
        >"$log_file" 2>&1; then
        # Write nax_root.conf for agent plugin
        [ "$name" = "agent_naxdarks_linux" ] && echo "$NAX_ROOT" > "$dest/nax_root.conf"
        echo -e "${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "${RED}✗ $name${NC}"
        echo ""
        # Show only the error lines, not the full make output
        grep -E "^#|error:|Error|undefined|cannot find|fatal error|syntax error" "$log_file" | head -20
        echo ""
        echo -e "${YELLOW}Full log: $log_file${NC}"
        return 1
    fi
}

# ===== DEPLOY ONLY =====

deploy_configs() {
    local pairs=(
        "agent_naxdarks_linux:$NAX_ROOT/agent_naxdarks_linux"
        "listener_naxdarks_linux_tcp:$NAX_ROOT/src_server/listener_naxdarks_linux_tcp"
        "listener_naxdarks_linux_https:$NAX_ROOT/src_server/listener_naxdarks_linux_https"
    )
    for pair in "${pairs[@]}"; do
        local name="${pair%%:*}"
        local src="${pair##*:}"
        local dest="$EXTENDERS_DIR/$name"
        mkdir -p "$dest"
        cp "$src/ax_config.axs" "$dest/" 2>/dev/null
        cp "$src/config.yaml"   "$dest/" 2>/dev/null
        echo -e "${GREEN}✓${NC} $name (configs)"
    done
}

# ===== PROFILE REGISTRATION =====

add_to_profile() {
    local yaml="$SERVER_DIR/profile.yaml"
    [ ! -f "$yaml" ] && return
    local entries=(
        "extenders/agent_naxdarks_linux/config.yaml"
        "extenders/listener_naxdarks_linux_tcp/config.yaml"
        "extenders/listener_naxdarks_linux_https/config.yaml"
    )
    for entry in "${entries[@]}"; do
        if ! grep -qF "$entry" "$yaml"; then
            sed -i "/^  extenders:/a\\    - \"$entry\"" "$yaml"
        fi
    done
}

# ===== MAIN =====

case $ACTION in
    all)
        check_prereqs
        detect_server_buildinfo
        failed=0
        build_plugin "agent_naxdarks_linux"           "agent-linux"           || failed=1
        build_plugin "listener_naxdarks_linux_tcp"     "listener-linux-tcp"    || failed=1
        build_plugin "listener_naxdarks_linux_https"   "listener-linux-https"  || failed=1
        [ $failed -eq 0 ] && add_to_profile
        [ $failed -ne 0 ] && exit 1
        ;;
    agent-linux)
        check_prereqs; detect_server_buildinfo
        build_plugin "agent_naxdarks_linux" "agent-linux" || exit 1
        add_to_profile
        ;;
    listener-linux-tcp)
        check_prereqs; detect_server_buildinfo
        build_plugin "listener_naxdarks_linux_tcp" "listener-linux-tcp" || exit 1
        add_to_profile
        ;;
    listener-linux-https)
        check_prereqs; detect_server_buildinfo
        build_plugin "listener_naxdarks_linux_https" "listener-linux-https" || exit 1
        add_to_profile
        ;;
    deploy)
        deploy_configs
        add_to_profile
        ;;
    prereqs)
        check_prereqs
        detect_server_buildinfo
        echo -e "${GREEN}✓${NC} prerequisites OK"
        ;;
    *)
        error_exit "Unknown action: $ACTION\nRun $0 --help for usage."
        ;;
esac
