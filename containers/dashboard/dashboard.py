from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

LOG_DIR = "/logs"
UNIFIED_LOG = f"{LOG_DIR}/unified.log"
ACTIONS_LOG = f"{LOG_DIR}/actions.log"

def read_log_file(filepath, max_lines=50):
    """Read last N lines from log file"""
    try:
        if not os.path.exists(filepath):
            return []
        
        with open(filepath, 'r') as f:
            lines = f.readlines()
            return [json.loads(line) for line in lines[-max_lines:]]
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/dashboard-data')
def dashboard_data():
    """Provide data for dashboard"""
    
    # Read logs
    unified_logs = read_log_file(UNIFIED_LOG)
    action_logs = read_log_file(ACTIONS_LOG)
    agent_decisions = read_log_file("/logs/agent_decisions.log", max_lines=20)
    
    # Parse incidents (FIXED VERSION)
    incidents = []
    seen_incidents = set()

    for log in unified_logs:
        if log.get('alert_type') or log.get('source') == 'detection-alert':
            alert_type = log.get('alert_type', 'Unknown')
            ip = log.get('ip', 'unknown')
        
            # Create unique key to avoid duplicates
            incident_key = f"{alert_type}:{ip}"
        
            if incident_key not in seen_incidents:
                seen_incidents.add(incident_key)
            
                # Determine severity based on alert type and confidence
                confidence = log.get('confidence', 0)
                if 'Brute' in alert_type:
                    severity = 'high'
                elif 'Credential' in alert_type:
                    severity = 'critical'
                else:
                    severity = 'medium'
            
                incidents.append({
                    'type': alert_type.replace('_', ' ').title(),
                    'description': f"Confidence: {confidence} - {log.get('failed_count', 0)} attempts",
                    'ip': ip,
                    'time': log.get('timestamp', '')[:19],
                    'severity': severity
                })	
    
    # Build timeline (existing code)
    timeline = []
    for log in unified_logs[-20:]:
        timeline.append({
            'time': log.get('timestamp', '')[:19],
            'description': f"{log.get('source', 'System')}: {log.get('event', 'event').replace('_', ' ').title()}"
        })
    
    # Parse agent decisions (NEW)
    decisions = []
    for decision in agent_decisions[-10:]:  # Last 10 decisions
        agent_name = decision.get('agent', 'Unknown Agent')
        output = decision.get('output', {})
        
        # Format based on agent type
        if 'Triage' in agent_name:
            decision_text = f"{output.get('status', 'N/A')} - Severity: {output.get('severity', 'N/A')}"
            reasoning = output.get('reason', 'No reasoning provided')
        elif 'Decision' in agent_name:
            decision_text = f"Action: {output.get('decision', 'N/A')}"
            reasoning = output.get('justification', 'No justification provided')
        elif 'Investigation' in agent_name:
            decision_text = f"Attack: {output.get('attack_type', 'Unknown')}"
            reasoning = output.get('analysis', 'No analysis provided')
        else:
            decision_text = str(output)
            reasoning = ""
        
        decisions.append({
            'agent': agent_name,
            'decision': decision_text,
            'reasoning': reasoning[:150]  # Limit length
        })
    
    # Parse actions (existing code)
    actions = []
    for action in action_logs:
        actions.append({
            'description': action.get('message', 'Action executed'),
            'status': action.get('status', 'unknown'),
            'time': action.get('timestamp', '')[:19]
        })
    
    # Calculate stats
    blocked_ips = len([a for a in action_logs if a.get('action') == 'block_ip' and a.get('status') == 'success'])

    # Count unique IPs from recent incidents (last 5)
    active_alert_ips = set()
    for incident in incidents[-5:]:
        if incident['severity'] in ['high', 'critical']:
            active_alert_ips.add(incident['ip'])

    return jsonify({
        'stats': {
            'total_incidents': len(incidents),
            'active_alerts': len(active_alert_ips),  # Unique high/critical IPs
            'blocked_ips': blocked_ips
        },
        'incidents': incidents[-10:],
        'timeline': timeline[-15:],
        'decisions': decisions,
        'actions': actions[-10:]
     })

if __name__ == '__main__':
    print("📊 Dashboard starting on port 80...")
    app.run(host='0.0.0.0', port=80)
