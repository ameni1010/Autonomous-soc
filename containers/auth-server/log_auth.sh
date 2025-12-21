#!/bin/bash

LOG_COLLECTOR="http://soc-logs:5000/ingest"
AUTH_LOG="/var/log/auth.log"

echo "Starting auth log monitor..."

tail -F "$AUTH_LOG" 2>/dev/null | while read -r line; do
  # Parse failed password attempts
  if echo "$line" | grep -q "Failed password"; then
    USER=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}')
    IP=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}')
    
    curl -s -X POST "$LOG_COLLECTOR" \
      -H "Content-Type: application/json" \
      -d "{
        \"timestamp\": \"$(date -Iseconds)\",
        \"source\": \"auth-server\",
        \"event\": \"login_failed\",
        \"user\": \"$USER\",
        \"ip\": \"$IP\"
      }" &
  fi
  
  # Parse successful logins
  if echo "$line" | grep -q "Accepted password"; then
    USER=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}')
    IP=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}')
    
    curl -s -X POST "$LOG_COLLECTOR" \
      -H "Content-Type: application/json" \
      -d "{
        \"timestamp\": \"$(date -Iseconds)\",
        \"source\": \"auth-server\",
        \"event\": \"login_success\",
        \"user\": \"$USER\",
        \"ip\": \"$IP\"
      }" &
  fi
  
  # Parse sudo commands (privilege escalation)
  if echo "$line" | grep -q "sudo.*COMMAND"; then
    USER=$(echo "$line" | awk '{print $6}' | cut -d: -f1)
    COMMAND=$(echo "$line" | awk -F'COMMAND=' '{print $2}')
    
    curl -s -X POST "$LOG_COLLECTOR" \
      -H "Content-Type: application/json" \
      -d "{
        \"timestamp\": \"$(date -Iseconds)\",
        \"source\": \"auth-server\",
        \"event\": \"privilege_escalation\",
        \"user\": \"$USER\",
        \"details\": {\"command\": \"$COMMAND\"}
      }" &
  fi
done
