#!/bin/bash

# ==========================================
# Colors for output
# ==========================================
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

# ==========================================
# Variables
# ==========================================
VERSION="V-1.6"
TUN_NAME="SUTAW-Gre"
UPDATE_URL="https://raw.githubusercontent.com/mdjes/SUTAW-Gre/main/sutaw-gre.sh"
SERVICE_FILE="/etc/systemd/system/sutaw-gre.service"
STARTUP_SCRIPT="/usr/local/bin/sutaw-gre-boot.sh"

# ==========================================
# Root Privilege Check
# ==========================================
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root. Use 'sudo mdtun'${RESET}"
   exit 1
fi

# ==========================================
# Auto Install as Global Command (sudo mdtun)
# ==========================================
CURRENT_SCRIPT=$(readlink -f "$0")
if [[ "$CURRENT_SCRIPT" != "/usr/local/bin/mdtun" ]]; then
    cp "$CURRENT_SCRIPT" /usr/local/bin/mdtun 2>/dev/null
    chmod +x /usr/local/bin/mdtun 2>/dev/null
    echo -e "${GREEN}[✓] Global Command Installed! You can now use 'sudo mdtun' from anywhere.${RESET}"
    sleep 2
fi

# ==========================================
# Menu Header
# ==========================================
clear
echo -e "${CYAN}"
echo "===================================="
echo "          GitHub: SUTAW"
echo "   SUTAW-Gre Tunnel Setup Script"
echo "             Version: $VERSION"
echo "     Run anytime with: sudo mdtun"
echo "------------------------------------"
echo "           T.ME/SUTAW"
echo "===================================="
echo -e "${RESET}"

echo "Select option:"
echo "1 - IRAN (Create Tunnel + Auto Start + Secure GRE)"
echo "2 - FOREIGN (Create Tunnel + Auto Start + Secure GRE)"
echo "3 - DELETE Tunnel (Remove tunnel, rules, and service)"
echo "4 - CHECK Status (Test tunnel connection and Ping)"
echo "5 - ENABLE BBR (Optimize Network Speed & Latency)"
echo "6 - INSTALL Prerequisites (Required packages)"
echo "7 - UPDATE Core (Update script from GitHub)"
echo "8 - SECURE Server (Anti-DDoS, Anti-Spoof, Fail2ban)"
echo "9 - EXIT"
echo

read -p "Enter a number (1-9): " OPTION

# ==========================================
# Helper Function: Create Systemd Service
# ==========================================
create_systemd_service() {
    cat <<EOF > $SERVICE_FILE
[Unit]
Description=SUTAW GRE Tunnel Persistence Service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$STARTUP_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sutaw-gre.service >/dev/null 2>&1
}

# ==========================================
# Main Logic
# ==========================================

if [[ "$OPTION" == "9" ]]; then
    echo -e "${YELLOW}[*] Exiting...${RESET}"
    exit 0
fi

if [[ "$OPTION" == "1" || "$OPTION" == "2" ]]; then
    read -p "Enter IRAN server IP: " IP_IRAN
    read -p "Enter FOREIGN server IP: " IP_FOREIGN
fi

if [[ "$OPTION" == "1" ]]; then
    echo -e "${YELLOW}[*] Generating config and persistence service for IRAN server...${RESET}"

    cat <<EOF > $STARTUP_SCRIPT
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
ip tunnel add $TUN_NAME mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
ip link set $TUN_NAME mtu 1436
ip link set $TUN_NAME up
ip addr add 132.168.30.2/30 dev $TUN_NAME

# Flushing old NAT rules to avoid conflicts
iptables -t nat -F

# SECURITY: Only allow GRE protocol (47) from the Foreign IP
iptables -D INPUT -p 47 ! -s $IP_FOREIGN -j DROP 2>/dev/null
iptables -I INPUT -p 47 ! -s $IP_FOREIGN -j DROP

# Port Forwarding Rules for SSH and Routing
iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2
iptables -t nat -A PREROUTING -j DNAT --to-destination 132.168.30.1
iptables -t nat -A POSTROUTING -j MASQUERADE
EOF
    chmod +x $STARTUP_SCRIPT
    create_systemd_service
    bash $STARTUP_SCRIPT

    echo -e "${GREEN}[✓] IRAN tunnel created and secured for reboots successfully.${RESET}"

elif [[ "$OPTION" == "2" ]]; then
    echo -e "${YELLOW}[*] Generating config and persistence service for FOREIGN server...${RESET}"

    cat <<EOF > $STARTUP_SCRIPT
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
ip tunnel add $TUN_NAME mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
ip link set $TUN_NAME mtu 1436
ip link set $TUN_NAME up
ip addr add 132.168.30.1/30 dev $TUN_NAME

# SECURITY: Only allow GRE protocol (47) from the Iran IP
iptables -D INPUT -p 47 ! -s $IP_IRAN -j DROP 2>/dev/null
iptables -I INPUT -p 47 ! -s $IP_IRAN -j DROP

# Drop ICMP requests on Foreign to hide server
iptables -D INPUT --proto icmp -j DROP 2>/dev/null
iptables -A INPUT --proto icmp -j DROP
EOF
    chmod +x $STARTUP_SCRIPT
    create_systemd_service
    bash $STARTUP_SCRIPT

    echo -e "${GREEN}[✓] FOREIGN tunnel created and secured for reboots successfully.${RESET}"

elif [[ "$OPTION" == "3" ]]; then
    echo -e "${RED}[*] Deleting SUTAW-Gre tunnel, rules, and boot service...${RESET}"

    systemctl stop sutaw-gre.service 2>/dev/null
    systemctl disable sutaw-gre.service 2>/dev/null
    rm -f $SERVICE_FILE
    rm -f $STARTUP_SCRIPT
    systemctl daemon-reload

    ip link set $TUN_NAME down 2>/dev/null  
    ip tunnel del $TUN_NAME 2>/dev/null  

    iptables -t nat -D PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2 2>/dev/null  
    iptables -t nat -D PREROUTING -j DNAT --to-destination 132.168.30.1 2>/dev/null  
    iptables -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null  
    iptables -D INPUT --proto icmp -j DROP 2>/dev/null  
    
    # Remove all GRE restrictive rules safely
    iptables -S INPUT | grep " -p 47 " | sed 's/-A /-D /g' | while read rule; do iptables $rule; done

    echo -e "${GREEN}[✓] Tunnel, firewall rules, and startup service completely removed.${RESET}"

elif [[ "$OPTION" == "4" ]]; then
    echo -e "${YELLOW}[*] Checking tunnel status...${RESET}"
    if ip link show $TUN_NAME > /dev/null 2>&1; then
        echo -e "${GREEN}[✓] Interface $TUN_NAME is UP!${RESET}"
        if ping -c 2 132.168.30.1 >/dev/null 2>&1 || ping -c 2 132.168.30.2 >/dev/null 2>&1; then
            echo -e "${GREEN}[✓] Connection is successful! Tunnel is fully operational.${RESET}"
        else
            echo -e "${RED}[!] Tunnel interface is up, but CANNOT ping the remote server.${RESET}"
        fi
    else
        echo -e "${RED}[!] Tunnel interface ($TUN_NAME) is DOWN or does not exist.${RESET}"
    fi

elif [[ "$OPTION" == "5" ]]; then
    echo -e "${YELLOW}[*] Optimizing Network and Enabling BBR...${RESET}"
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo -e "${GREEN}[✓] BBR is successfully enabled! Speed optimized.${RESET}"

elif [[ "$OPTION" == "6" ]]; then
    echo -e "${YELLOW}[*] Installing Prerequisites...${RESET}"
    apt-get update -y
    apt-get install -y iproute2 iptables curl ufw grep fail2ban
    echo -e "${GREEN}[✓] All required packages installed.${RESET}"

elif [[ "$OPTION" == "7" ]]; then
    echo -e "${YELLOW}[*] Updating SUTAW-Gre core from GitHub...${RESET}"
    
    TMP_FILE=$(mktemp)
    if curl -fsSL "$UPDATE_URL" -o "$TMP_FILE"; then
        cat "$TMP_FILE" > /usr/local/bin/mdtun
        chmod +x /usr/local/bin/mdtun
        rm -f "$TMP_FILE"
        
        if [[ "$CURRENT_SCRIPT" != "/usr/local/bin/mdtun" && -f "$CURRENT_SCRIPT" ]]; then
            cat /usr/local/bin/mdtun > "$CURRENT_SCRIPT"
        fi
        
        echo -e "${GREEN}[✓] Update completed successfully.${RESET}"
        echo -e "${GREEN}[*] Please re-run using command: ${YELLOW}sudo mdtun${RESET}"  
        exit 0
    else
        echo -e "${RED}[!] Update failed. Network issue or GitHub URL is invalid.${RESET}"
        rm -f "$TMP_FILE"
        exit 1
    fi

elif [[ "$OPTION" == "8" ]]; then
    echo -e "${YELLOW}[*] Applying Security Hardening (Kernel & Firewall)...${RESET}"
    
    # 1. Kernel Level Security tweaks
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.all.accept_redirects/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.all.send_redirects/d' /etc/sysctl.conf
    
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    
    # 2. Drop Invalid Packets via iptables (Prevents certain scans/attacks)
    iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    
    # 3. Fail2ban setup for SSH protection
    apt-get update -y >/dev/null 2>&1
    apt-get install -y fail2ban >/dev/null 2>&1
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1

    echo -e "${GREEN}[✓] Anti-DDoS, IP Spoofing protection, and Fail2ban applied successfully!${RESET}"

else
    echo -e "${RED}[!] Invalid selection. Run the script again and select a number from 1 to 9.${RESET}"
    exit 1
fi
