#!/bin/bash

CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

TUN_NAME="SUTAW-Gre"

echo -e "${CYAN}"
echo "===================================="
echo "        GitHub: SUTAW"
echo "   SUTAW-Gre Tunnel Setup Script"
echo "===================================="
echo -e "${RESET}"

echo "Select option:"
echo "1 - IRAN (Create Tunnel)"
echo "2 - FOREIGN (Create Tunnel)"
echo "3 - DELETE Tunnel (Remove tunnel and firewall rules)"
echo
echo "Telegram: T.ME/SUTAW"
echo

read -p "Enter 1, 2 or 3: " OPTION

if [[ "$OPTION" == "1" || "$OPTION" == "2" ]]; then
    read -p "Enter IRAN server IP: " IP_IRAN
    read -p "Enter FOREIGN server IP: " IP_FOREIGN
fi

if [[ "$OPTION" == "1" ]]; then
    echo "[*] Running config for IRAN server..."

    sudo ip tunnel add $TUN_NAME mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    sudo ip link set $TUN_NAME up
    sudo ip addr add 132.168.30.2/30 dev $TUN_NAME

    sysctl -w net.ipv4.ip_forward=1

    iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2
    iptables -t nat -A PREROUTING -j DNAT --to-destination 132.168.30.1
    iptables -t nat -A POSTROUTING -j MASQUERADE

    echo "[✓] IRAN tunnel created successfully."

elif [[ "$OPTION" == "2" ]]; then
    echo "[*] Running config for FOREIGN server..."

    sudo ip tunnel add $TUN_NAME mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    sudo ip link set $TUN_NAME up
    sudo ip addr add 132.168.30.1/30 dev $TUN_NAME

    sudo iptables -A INPUT --proto icmp -j DROP

    echo "[✓] FOREIGN tunnel created successfully."

elif [[ "$OPTION" == "3" ]]; then
    echo -e "${RED}[*] Deleting SUTAW-Gre tunnel and rules...${RESET}"

    # Remove tunnel
    sudo ip link set $TUN_NAME down 2>/dev/null
    sudo ip tunnel del $TUN_NAME 2>/dev/null

    # Cleanup iptables rules
    iptables -t nat -D PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2 2>/dev/null
    iptables -t nat -D PREROUTING -j DNAT --to-destination 132.168.30.1 2>/dev/null
    iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null
    iptables -D INPUT --proto icmp -j DROP 2>/dev/null

    echo "[✓] Tunnel and firewall rules removed."

else
    echo "[!] Invalid selection."
    exit 1
fi
