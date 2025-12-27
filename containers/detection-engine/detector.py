from flask import Flask, request, jsonify, Response
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import requests
import os

app = Flask(__name__)

# In-memory state
failed_logins = defaultdict(list)
successful_logins = {}
privilege_events = []

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)

def clean_old_data():
    cutoff = datetime.now(timezone.utc) - TIME_WINDOW
    
    for ip in list(failed_logins.keys()):
        failed_logins[ip] = [
            t for t in failed_logins[ip] 
            if (t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t) > cutoff
        ]
        if not failed_logins[ip]:
            del failed_logins[ip]

def parse_timestamp(timestamp_str):
    if not timestamp_str:
        return datetime.now(timezone.utc)
    
    try:
        clean_ts = timestamp_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except:
        try:
            dt = datetime.fromisoformat(timestamp_str.split('+')[0].split('Z')[0])
            return dt.replace(tzinfo=timezone.utc)
        except:
            return datetime.now(timezone.utc)

@app.route('/analyze', methods=['POST'])
def analyze():
    alerts = []
    
    try:
        log = request.get_json(force=True)
        
        if not log:
            return jsonify({"error": "No data"}), 400
        
        event_type = log.get('event')
        ip = log.get('ip')
        user = log.get('user')
        timestamp = parse_timestamp(log.get('timestamp'))
        
        print(f"[ANALYZE] Event: {event_type}, IP: {ip}, User: {user}")
        
        clean_old_data()
        
        # Brute Force Detection
        if event_type == 'login_failed' and ip:
            failed_logins[ip].append(timestamp)
            print(f"[DETECT] Failed login from {ip}, total: {len(failed_logins[ip])}")
            
            if len(failed_logins[ip]) == BRUTE_FORCE_THRESHOLD:
                alert = {
                    "alert_id": f"BF-{ip}-{int(timestamp.timestamp())}",
                    "alert_type": "BruteForceSuspected",
                    "confidence": 0.85,
                    "ip": ip,
                    "user": user or "unknown",
                    "failed_count": len(failed_logins[ip]),
                    "timestamp": timestamp.isoformat(),
                    "source": "detection-alert"
                }
                alerts.append(alert)
                print(f"🚨 ALERT: Brute force detected from {ip}")
                
                try:
                    os.makedirs('/logs', exist_ok=True)
                    with open('/logs/unified.log', 'a') as f:
                        f.write(json.dumps(alert) + '\n')
                    print("[SAVED] Alert written to unified.log")
                except Exception as e:
                    print(f"[ERROR] Failed to save alert: {e}")
                
                send_to_n8n(alert)
        
        # Credential Compromise
        elif event_type == 'login_success' and ip:
            if ip in failed_logins and len(failed_logins[ip]) > 0:
                alert = {
                    "alert_id": f"COMP-{ip}-{int(timestamp.timestamp())}",
                    "alert_type": "PossibleCredentialCompromise",
                    "confidence": 0.90,
                    "ip": ip,
                    "user": user or "unknown",
                    "timestamp": timestamp.isoformat(),
                    "source": "detection-alert"
                }
                alerts.append(alert)
                print(f"🚨 ALERT: Credential compromise - {user}@{ip}")
                
                try:
                    os.makedirs('/logs', exist_ok=True)
                    with open('/logs/unified.log', 'a') as f:
                        f.write(json.dumps(alert) + '\n')
                    print("[SAVED] Alert written to unified.log")
                except Exception as e:
                    print(f"[ERROR] Failed to save alert: {e}")
                
                send_to_n8n(alert)
        
        return jsonify({"status": "analyzed", "alerts": alerts}), 200
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return Response(
            json.dumps({"error": str(e)}),
            status=500,
            mimetype='application/json'
        )

def send_to_n8n(alert):
    try:
        response = requests.post(
            'http://soc-n8n:5678/webhook/soc-alert',
            json=alert,
            timeout=3
        )
        print(f"✅ Alert sent to n8n: {alert['alert_type']}, Status: {response.status_code}")
        if response.status_code != 200:
            print(f"   Response: {response.text}")
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
