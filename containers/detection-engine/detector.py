from flask import Flask, request, jsonify
from collections import defaultdict
from datetime import datetime, timedelta
import json
import requests

app = Flask(__name__)

# In-memory state for detection
failed_logins = defaultdict(list)
successful_logins = {}
privilege_events = []

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)

def clean_old_data():
    """Remove old entries outside time window"""
    cutoff = datetime.utcnow() - TIME_WINDOW
    
    for ip in list(failed_logins.keys()):
        failed_logins[ip] = [t for t in failed_logins[ip] if t > cutoff]
        if not failed_logins[ip]:
            del failed_logins[ip]

@app.route('/analyze', methods=['POST'])
def analyze():
    """Detect suspicious patterns in logs"""
    try:
        log = request.json
        event_type = log.get('event')
        ip = log.get('ip')
        user = log.get('user')
        timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
        
        alerts = []
        
        # Clean old data
        clean_old_data()
        
        # Pattern 1: Brute Force Detection
        if event_type == 'login_failed':
            failed_logins[ip].append(timestamp)
            
            if len(failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
                alert = {
                    "alert_id": f"BF-{ip}-{int(timestamp.timestamp())}",
                    "alert_type": "BruteForceSuspected",
                    "confidence": 0.85 + (len(failed_logins[ip]) * 0.02),
                    "ip": ip,
                    "user": user,
                    "failed_count": len(failed_logins[ip]),
                    "timestamp": timestamp.isoformat(),
                    "details": {
                        "pattern": "Multiple failed login attempts detected",
                        "time_window": "5 minutes"
                    }
                }
                alerts.append(alert)
                print(f"🚨 ALERT: Brute force detected from {ip} ({len(failed_logins[ip])} attempts)")
                send_to_n8n(alert)
        
        # Pattern 2: Successful login after failed attempts
        elif event_type == 'login_success':
            successful_logins[ip] = {
                "user": user,
                "timestamp": timestamp
            }
            
            if ip in failed_logins and len(failed_logins[ip]) > 0:
                alert = {
                    "alert_id": f"COMP-{ip}-{int(timestamp.timestamp())}",
                    "alert_type": "PossibleCredentialCompromise",
                    "confidence": 0.90,
                    "ip": ip,
                    "user": user,
                    "timestamp": timestamp.isoformat(),
                    "details": {
                        "pattern": "Successful login after multiple failed attempts",
                        "previous_failures": len(failed_logins[ip])
                    }
                }
                alerts.append(alert)
                print(f"🚨 ALERT: Possible credential compromise - {user}@{ip}")
                send_to_n8n(alert)
        
        # Pattern 3: Privilege escalation after suspicious activity
        elif event_type == 'privilege_escalation':
            privilege_events.append({
                "user": user,
                "timestamp": timestamp,
                "details": log.get('details', {})
            })
            
            if ip in failed_logins and len(failed_logins[ip]) > 0:
                alert = {
                    "alert_id": f"PE-{ip}-{int(timestamp.timestamp())}",
                    "alert_type": "PrivilegeEscalationAfterBrute",
                    "confidence": 0.95,
                    "ip": ip,
                    "user": user,
                    "timestamp": timestamp.isoformat(),
                    "details": {
                        "pattern": "Privilege escalation after failed login attempts",
                        "command": log.get('details', {}).get('command', 'unknown')
                    }
                }
                alerts.append(alert)
                print(f"🚨 CRITICAL ALERT: Privilege escalation detected - {user}@{ip}")
                send_to_n8n(alert)
        
        return jsonify({"status": "analyzed", "alerts": alerts}), 200
        
    except Exception as e:
        print(f"Error analyzing log: {e}")
        return jsonify({"error": str(e)}), 500

def send_to_n8n(alert):
    """Send alert to n8n webhook for agent processing"""
    try:
        response = requests.post(
            'http://soc-n8n:5678/webhook/soc-alert',
            json=alert,
            timeout=3
        )
        print(f"✅ Alert sent to n8n: {alert['alert_type']}")
    except Exception as e:
        print(f"❌ Failed to send to n8n: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "detection-engine",
        "active_ips": len(failed_logins)
    }), 200

if __name__ == '__main__':
    print("🔍 Detection Engine starting on port 5001...")
    app.run(host='0.0.0.0', port=5001)
