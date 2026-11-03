
#!/usr/bin/env bash
# ==========================================================
# SUTAW-Gre v2.1.0
# Professional GRE Tunnel Manager
#
# Features:
# - Iran / Foreign GRE setup
# - TCP / UDP forwarding
# - SSH preservation
# - Dedicated iptables chains
# - Policy routing
# - Systemd auto startup
# - Safe removal
# - GitHub self updater
# - Cache-busting updates
# ==========================================================

set -Eeuo pipefail

VERSION="2.1.0"

UPDATE_URL="https://raw.githubusercontent.com/mdjes/SUTAW-Gre/main/sutaw-gre.sh"

NAME="SUTAW-Gre"
TUN="SUTAW-Gre"

INSTALL_PATH="/usr/local/sbin/sutaw-gre.sh"
CONFIG="/etc/sutaw-gre.conf"
SERVICE="/etc/systemd/system/sutaw-gre.service"
STATE_DIR="/var/lib/sutaw-gre"

IRAN_TUN_IP="10.200.200.1"
FOREIGN_TUN_IP="10.200.200.2"

TABLE="52000"
PRIORITY="10500"
MARK="0x535554"

C_INPUT="SUTAWG_IN"
C_FORWARD="SUTAWG_FWD"
C_MANGLE="SUTAWG_MPR"
C_NAT_PRE="SUTAWG_NPR"
C_NAT_POST="SUTAWG_POST"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

require_root() {
    [[ "$EUID" -eq 0 ]] || die "Run as root."
}

dependencies() {
    local missing=()

    for cmd in ip iptables sysctl python3 systemctl ping; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    ((${#missing[@]} == 0)) ||
        die "Missing dependencies: ${missing[*]}. Select option 7."
}

require_curl() {
    command -v curl >/dev/null 2>&1 ||
        die "curl is missing. Select option 7."
}

valid_ip() {
    python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
    sys.exit(0 if address.version == 4 and not address.is_unspecified else 1)
except ValueError:
    sys.exit(1)
PY
}

load_config() {
    [[ -f "$CONFIG" ]] || die "Configuration not found."

    source "$CONFIG"

    [[ "${ROLE:-}" == "iran" || "${ROLE:-}" == "foreign" ]] ||
        die "Invalid role."

    valid_ip "${IRAN_IP:-}" || die "Invalid Iran IPv4."
    valid_ip "${FOREIGN_IP:-}" || die "Invalid Foreign IPv4."

    [[ "$IRAN_IP" != "$FOREIGN_IP" ]] ||
        die "Public IPs cannot be identical."

    [[ "${SSH_PORT:-}" =~ ^[0-9]+$ ]] &&
        ((SSH_PORT >= 1 && SSH_PORT <= 65535)) ||
        die "Invalid SSH port."
}

# ==========================================================
# GITHUB UPDATE ENGINE
# ==========================================================

download_latest() {
    require_root
    require_curl

    local temp_file
    local new_file
    local url

    mkdir -p "$(dirname "$INSTALL_PATH")"

    temp_file=$(mktemp /tmp/sutaw-update.XXXXXX)
    new_file="${INSTALL_PATH}.new.$$"

    # Cache busting prevents stale CDN responses.
    url="${UPDATE_URL}?cache=$(date +%s%N)"

    log "Downloading latest SUTAW-Gre from GitHub..."

    if ! curl \
        --fail \
        --location \
        --silent \
        --show-error \
        --retry 2 \
        --connect-timeout 15 \
        --max-time 120 \
        "$url" \
        -o "$temp_file"; then

        rm -f "$temp_file" "$new_file"
        die "GitHub download failed."
    fi

    # Validate downloaded file.
    if ! grep -q 'SUTAW-Gre' "$temp_file"; then
        rm -f "$temp_file" "$new_file"
        die "Invalid downloaded file."
    fi

    if ! grep -Eq '^VERSION="[0-9]+\.[0-9]+\.[0-9]+"' "$temp_file"; then
        rm -f "$temp_file" "$new_file"
        die "Version information missing."
    fi

    if ! bash -n "$temp_file"; then
        rm -f "$temp_file" "$new_file"
        die "Downloaded script has syntax errors."
    fi

    # Extract downloaded version.
    local new_version

    new_version=$(grep -m1 '^VERSION=' "$temp_file" |
        cut -d'"' -f2)

    # Install to a temporary file on the same filesystem.
    install -m 0755 "$temp_file" "$new_file"

    # Atomic replacement.
    mv -f "$new_file" "$INSTALL_PATH"

    rm -f "$temp_file"

    ok "SUTAW-Gre updated successfully."
    ok "Installed version: $new_version"
}

update_core() {
    download_latest

    echo
    ok "Restarting with the latest version..."

    exec "$INSTALL_PATH"
}

# ==========================================================
# IPTABLES MANAGEMENT
# ==========================================================

ipt() {
    iptables -w 10 "$@"
}

ensure_chain() {
    local table="$1"
    local chain="$2"

    ipt -t "$table" -N "$chain" 2>/dev/null || true
    ipt -t "$table" -F "$chain"
}

remove_jump() {
    local table="$1"
    local parent="$2"
    local child="$3"

    while ipt -t "$table" -C "$parent" -j "$child" 2>/dev/null; do
        ipt -t "$table" -D "$parent" -j "$child" || break
    done
}

ensure_jump() {
    local table="$1"
    local parent="$2"
    local child="$3"

    remove_jump "$table" "$parent" "$child"
    ipt -t "$table" -I "$parent" 1 -j "$child"
}

remove_chain() {
    local table="$1"
    local chain="$2"

    case "$table:$chain" in
        filter:SUTAWG_IN)
            remove_jump filter INPUT "$chain"
            ;;
        filter:SUTAWG_FWD)
            remove_jump filter FORWARD "$chain"
            ;;
        mangle:SUTAWG_MPR)
            remove_jump mangle PREROUTING "$chain"
            ;;
        nat:SUTAWG_NPR)
            remove_jump nat PREROUTING "$chain"
            ;;
        nat:SUTAWG_POST)
            remove_jump nat POSTROUTING "$chain"
            ;;
    esac

    ipt -t "$table" -F "$chain" 2>/dev/null || true
    ipt -t "$table" -X "$chain" 2>/dev/null || true
}

# ==========================================================
# NETWORK MANAGEMENT
# ==========================================================

detect_interface() {
    local peer="$1"

    WAN_IF=$(ip -4 route get "$peer" |
        awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

    [[ -n "${WAN_IF:-}" ]] ||
        die "Cannot detect WAN interface."

    log "WAN interface: $WAN_IF"
}

check_local_ip() {
    ip -o -4 addr show |
        awk '{print $4}' |
        cut -d/ -f1 |
        grep -Fxq "$LOCAL_IP" ||
        die "Local IP $LOCAL_IP is not assigned to this server."
}

configure_tunnel() {
    log "Creating GRE interface..."

    ip tunnel del "$TUN" 2>/dev/null || true

    ip tunnel add "$TUN" mode gre \
        local "$LOCAL_IP" \
        remote "$PEER_IP" \
        ttl 255

    ip link set "$TUN" mtu 1476

    ip addr add "$LOCAL_TUN_IP/30" dev "$TUN"

    ip link set "$TUN" up

    ok "GRE interface configured."
}

save_state() {
    mkdir -p "$STATE_DIR"

    if [[ ! -f "$STATE_DIR/original_ip_forward" ]]; then
        sysctl -n net.ipv4.ip_forward \
            > "$STATE_DIR/original_ip_forward"
    fi
}

enable_forwarding() {
    save_state

    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ok "IPv4 forwarding enabled."
}

# ==========================================================
# FIREWALL CONFIGURATION
# ==========================================================

configure_input() {
    ensure_chain filter "$C_INPUT"
    ensure_jump filter INPUT "$C_INPUT"

    # Permit GRE only from the configured peer.
    ipt -A "$C_INPUT" \
        -p 47 \
        -s "$PEER_IP" \
        -j ACCEPT

    # Permit ICMP between tunnel endpoints.
    ipt -A "$C_INPUT" \
        -i "$TUN" \
        -s "$PEER_TUN_IP" \
        -d "$LOCAL_TUN_IP" \
        -p icmp \
        -j ACCEPT

    if [[ "$ROLE" == "foreign" ]]; then

        # Allow TCP services forwarded from Iran.
        ipt -A "$C_INPUT" \
            -i "$TUN" \
            -s "$IRAN_TUN_IP" \
            -d "$FOREIGN_IP" \
            -p tcp \
            -j ACCEPT

        # Allow UDP services forwarded from Iran.
        ipt -A "$C_INPUT" \
            -i "$TUN" \
            -s "$IRAN_TUN_IP" \
            -d "$FOREIGN_IP" \
            -p udp \
            -j ACCEPT
    fi
}

configure_iran_forwarding() {
    ensure_chain filter "$C_FORWARD"
    ensure_jump filter FORWARD "$C_FORWARD"

    ensure_chain mangle "$C_MANGLE"
    ensure_jump mangle PREROUTING "$C_MANGLE"

    ensure_chain nat "$C_NAT_PRE"
    ensure_jump nat PREROUTING "$C_NAT_PRE"

    ensure_chain nat "$C_NAT_POST"
    ensure_jump nat POSTROUTING "$C_NAT_POST"

    # Mark incoming TCP except SSH.
    ipt -t mangle -A "$C_MANGLE" \
        -i "$WAN_IF" \
        -d "$IRAN_IP" \
        -p tcp \
        ! --dport "$SSH_PORT" \
        -j MARK --set-xmark "$MARK/0xffffffff"

    # Mark incoming UDP.
    ipt -t mangle -A "$C_MANGLE" \
        -i "$WAN_IF" \
        -d "$IRAN_IP" \
        -p udp \
        -j MARK --set-xmark "$MARK/0xffffffff"

    # DNAT TCP.
    ipt -t nat -A "$C_NAT_PRE" \
        -i "$WAN_IF" \
        -d "$IRAN_IP" \
        -p tcp \
        ! --dport "$SSH_PORT" \
        -j DNAT --to-destination "$FOREIGN_IP"

    # DNAT UDP.
    ipt -t nat -A "$C_NAT_PRE" \
        -i "$WAN_IF" \
        -d "$IRAN_IP" \
        -p udp \
        -j DNAT --to-destination "$FOREIGN_IP"

    # SNAT through GRE.
    ipt -t nat -A "$C_NAT_POST" \
        -o "$TUN" \
        -d "$FOREIGN_IP" \
        -j SNAT --to-source "$IRAN_TUN_IP"

    # Permit outgoing TCP forwarding.
    ipt -A "$C_FORWARD" \
        -i "$WAN_IF" \
        -o "$TUN" \
        -d "$FOREIGN_IP" \
        -p tcp \
        -j ACCEPT

    # Permit outgoing UDP forwarding.
    ipt -A "$C_FORWARD" \
        -i "$WAN_IF" \
        -o "$TUN" \
        -d "$FOREIGN_IP" \
        -p udp \
        -j ACCEPT

    # Permit established return traffic.
    ipt -A "$C_FORWARD" \
        -i "$TUN" \
        -o "$WAN_IF" \
        -s "$IRAN_IP" \
        -m conntrack \
        --ctstate ESTABLISHED,RELATED \
        -j ACCEPT

    # Ensure routing priority is free.
    if ip rule show | grep -q "^${PRIORITY}:"; then
        die "Routing priority $PRIORITY is occupied."
    fi

    # Do not overwrite an existing routing table.
    if ip route show table "$TABLE" | grep -q .; then
        die "Routing table $TABLE is already in use."
    fi

    ip route add default dev "$TUN" table "$TABLE"

    ip rule add priority "$PRIORITY" \
        fwmark "$MARK/0xffffffff" \
        table "$TABLE"

    enable_forwarding

    ok "Iran forwarding configured."
}

configure_foreign() {
    log "Configuring foreign endpoint..."

    # The foreign endpoint receives forwarded TCP/UDP
    # as local INPUT traffic. No DNAT is needed here.

    ok "Foreign endpoint configured."
}

# ==========================================================
# CLEANUP
# ==========================================================

cleanup_runtime() {
    remove_chain filter "$C_INPUT"
    remove_chain filter "$C_FORWARD"
    remove_chain mangle "$C_MANGLE"
    remove_chain nat "$C_NAT_PRE"
    remove_chain nat "$C_NAT_POST"

    while ip rule del priority "$PRIORITY" \
        fwmark "$MARK/0xffffffff" \
        table "$TABLE" 2>/dev/null; do
        :
    done

    while ip route del default dev "$TUN" \
        table "$TABLE" 2>/dev/null; do
        :
    done

    ip link set "$TUN" down 2>/dev/null || true
    ip tunnel del "$TUN" 2>/dev/null || true
}

# ==========================================================
# APPLY CONFIGURATION
# ==========================================================

rollback_on_error() {
    local rc=$?
    trap - ERR

    warn "Configuration failed. Rolling back SUTAW resources."

    cleanup_runtime || true

    exit "$rc"
}

apply() {
    require_root
    dependencies
    load_config

    if [[ "$ROLE" == "iran" ]]; then
        LOCAL_IP="$IRAN_IP"
        PEER_IP="$FOREIGN_IP"
        LOCAL_TUN_IP="$IRAN_TUN_IP"
        PEER_TUN_IP="$FOREIGN_TUN_IP"
    else
        LOCAL_IP="$FOREIGN_IP"
        PEER_IP="$IRAN_IP"
        LOCAL_TUN_IP="$FOREIGN_TUN_IP"
        PEER_TUN_IP="$IRAN_TUN_IP"
    fi

    detect_interface "$PEER_IP"
    check_local_ip

    trap rollback_on_error ERR

    log "Applying SUTAW-Gre v$VERSION on $ROLE..."

    cleanup_runtime

    configure_tunnel

    if [[ "$ROLE" == "iran" ]]; then
        configure_iran_forwarding
    else
        configure_foreign
    fi

    configure_input

    trap - ERR

    ok "SUTAW-Gre successfully configured."
}

stop_runtime() {
    require_root
    dependencies

    log "Stopping SUTAW-Gre..."

    cleanup_runtime

    ok "Tunnel stopped."
}

# ==========================================================
# SYSTEMD
# ==========================================================

install_service() {
    log "Installing latest core..."

    # Never depend on /dev/fd or BASH_SOURCE.
    download_latest

    cat > "$SERVICE" <<EOF
[Unit]
Description=SUTAW-Gre Professional GRE Tunnel
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_PATH apply
ExecStop=$INSTALL_PATH stop-runtime
TimeoutStartSec=60
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sutaw-gre.service >/dev/null

    ok "Systemd service installed."
}

# ==========================================================
# INSTALLATION
# ==========================================================

setup() {
    require_root
    dependencies
    require_curl

    local role="$1"
    local iran foreign ssh

    echo
    echo "======================================"
    echo "       SUTAW-Gre Installation"
    echo "======================================"

    read -rp "Iran public IPv4: " iran
    read -rp "Foreign public IPv4: " foreign
    read -rp "Iran SSH port [22]: " ssh

    ssh="${ssh:-22}"

    valid_ip "$iran" || die "Invalid Iran IPv4."
    valid_ip "$foreign" || die "Invalid Foreign IPv4."

    [[ "$iran" != "$foreign" ]] ||
        die "Public IPs cannot be identical."

    [[ "$ssh" =~ ^[0-9]+$ ]] &&
        ((ssh >= 1 && ssh <= 65535)) ||
        die "Invalid SSH port."

    mkdir -p "$STATE_DIR"

    cat > "$CONFIG" <<EOF
ROLE='$role'
IRAN_IP='$iran'
FOREIGN_IP='$foreign'
SSH_PORT='$ssh'
EOF

    chmod 600 "$CONFIG"

    install_service

    systemctl restart sutaw-gre.service

    ok "Installation completed on $role server."
    ok "Automatic startup enabled."
}

# ==========================================================
# REMOVE
# ==========================================================

remove_all() {
    require_root
    dependencies

    log "Removing SUTAW-Gre..."

    systemctl disable --now sutaw-gre.service 2>/dev/null || true

    cleanup_runtime

    if [[ -f "$STATE_DIR/original_ip_forward" ]]; then
        local old

        old=$(cat "$STATE_DIR/original_ip_forward")

        sysctl -w "net.ipv4.ip_forward=$old" >/dev/null || true
    fi

    rm -f "$CONFIG"
    rm -f "$SERVICE"
    rm -rf "$STATE_DIR"

    systemctl daemon-reload

    systemctl reset-failed sutaw-gre.service 2>/dev/null || true

    ok "SUTAW-Gre removed."
}

# ==========================================================
# STATUS
# ==========================================================

status() {
    require_root

    echo
    echo "======================================"
    echo "          SUTAW-Gre STATUS"
    echo "======================================"

    if ! ip link show "$TUN" >/dev/null 2>&1; then
        warn "GRE interface does not exist."
    else
        ip -br link show "$TUN"
        ip -br addr show "$TUN"

        if [[ -f "$CONFIG" ]]; then
            load_config

            local target

            if [[ "$ROLE" == "iran" ]]; then
                target="$FOREIGN_TUN_IP"
            else
                target="$IRAN_TUN_IP"
            fi

            if ping -I "$TUN" -c 3 -W 2 "$target" >/dev/null 2>&1; then
                ok "Remote GRE endpoint reachable."
            else
                warn "Remote GRE endpoint not responding."
            fi
        fi
    fi

    echo
    echo "---- Systemd ----"

    systemctl status sutaw-gre.service \
        --no-pager -l 2>/dev/null || true

    echo
    echo "---- GRE Statistics ----"

    ip -s link show "$TUN" 2>/dev/null || true

    echo
    echo "---- Routing ----"

    ip rule show | grep "$PRIORITY" || true
    ip route show table "$TABLE" || true

    echo
    echo "======================================"
}

# ==========================================================
# PREREQUISITES
# ==========================================================

install_prerequisites() {
    require_root

    command -v apt-get >/dev/null 2>&1 ||
        die "Only Debian/Ubuntu supported."

    log "Installing prerequisites..."

    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 \
        iptables \
        iputils-ping \
        python3 \
        curl \
        ca-certificates

    ok "Prerequisites installed."
}

# ==========================================================
# MENU
# ==========================================================

menu() {
    echo
    echo -e "${CYAN}"
    echo "======================================"
    echo "              SUTAW-Gre"
    echo "       Professional GRE Manager"
    echo "              v$VERSION"
    echo "======================================"
    echo -e "${RESET}"

    echo "1 - INSTALL IRAN"
    echo "2 - INSTALL FOREIGN"
    echo "3 - DELETE TUNNEL"
    echo "4 - CHECK STATUS"
    echo "5 - START TUNNEL"
    echo "6 - STOP TUNNEL"
    echo "7 - INSTALL PREREQUISITES"
    echo "8 - UPDATE FROM GITHUB"
    echo "9 - EXIT"

    echo

    read -rp "Select option (1-9): " option

    case "$option" in
        1)
            setup iran
            ;;
        2)
            setup foreign
            ;;
        3)
            remove_all
            ;;
        4)
            status
            ;;
        5)
            require_root
            systemctl start sutaw-gre.service
            ;;
        6)
            require_root
            systemctl stop sutaw-gre.service
            ;;
        7)
            install_prerequisites
            ;;
        8)
            update_core
            ;;
        9)
            exit 0
            ;;
        *)
            die "Invalid selection."
            ;;
    esac
}

# ==========================================================
# ENTRY POINT
# ==========================================================

case "${1:-}" in
    apply)
        apply
        ;;
    stop-runtime)
        stop_runtime
        ;;
    *)
        require_root
        menu
        ;;
esac
