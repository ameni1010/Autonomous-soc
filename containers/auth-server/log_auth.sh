#!/bin/bash

LOG_COLLECTOR="http://soc-logs:5000/ingest"

echo "Starting auth log monitor..."

# Monitor auth logs from journalctl/syslog
tail -F /var/log/syslog 2>/dev/null | while read -r line; do
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
done
