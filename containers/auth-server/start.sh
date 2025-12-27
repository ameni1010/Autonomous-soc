#!/bin/bash

LOG_COLLECTOR="http://soc-logs:5000/ingest"

# Function to send logs (only called when new auth event happens)
send_log() {
    local event=$1
    local user=$2
    local ip=$3
    
    curl -s -X POST "$LOG_COLLECTOR" \
      -H "Content-Type: application/json" \
      -d "{
        \"timestamp\": \"$(date -Iseconds)\",
        \"source\": \"auth-server\",
        \"event\": \"$event\",
        \"user\": \"$user\",
        \"ip\": \"$ip\"
      }" &
}

echo "Starting SSH with inline logging..."

# Start SSH and parse logs inline (single process)
/usr/sbin/sshd -D -e 2>&1 | while IFS= read -r line; do
    
    # Only log actual auth events (not every line)
    if echo "$line" | grep -qi "Failed password"; then
        USER=$(echo "$line" | grep -oE "for [^ ]+ " | awk '{print $2}' | head -1)
        IP=$(echo "$line" | grep -oE "from [0-9.]+ " | awk '{print $2}' | head -1)
        
        if [ ! -z "$IP" ]; then
            echo "[AUTH] Failed: $USER@$IP"
            send_log "login_failed" "$USER" "$IP"
        fi
        
    elif echo "$line" | grep -qi "Accepted password"; then
        USER=$(echo "$line" | grep -oE "for [^ ]+ " | awk '{print $2}' | head -1)
        IP=$(echo "$line" | grep -oE "from [0-9.]+ " | awk '{print $2}' | head -1)
        
        if [ ! -z "$IP" ]; then
            echo "[AUTH] Success: $USER@$IP"
            send_log "login_success" "$USER" "$IP"
        fi
    fi
done
