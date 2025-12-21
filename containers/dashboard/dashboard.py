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
    
    # Parse incidents
    incidents = []
    for log in unified_logs:
        if log.get('event') in ['login_failed', 'privilege_escalation']:
            incidents.append({
                'type': log.get('event', 'Unknown').replace('_', ' ').title(),
                'description': f"User: {log.get('user', 'unknown')} from IP {log.get('ip', 'unknown')}",
                'ip': log.get('ip', 'unknown'),
                'time': log.get('timestamp', '')[:19],
                'severity': 'high' if log.get('event') == 'privilege_escalation' else 'medium'
            })
    
    # Build timeline
    timeline = []
    for log in unified_logs[-20:]:
        timeline.append({
            'time': log.get('timestamp', '')[:19],
            'description': f"{log.get('source', 'System')}: {log.get('event', 'event').replace('_', ' ').title()}"
        })
    
    # Mock decisions (would come from agent logs in production)
    decisions = []
    if len(incidents) > 0:
        decisions.append({
            'agent': 'Triage Agent',
            'decision': 'Valid security alert detected',
            'reasoning': 'Multiple failed login attempts followed by successful login'
        })
        decisions.append({
            'agent': 'Decision Agent',
            'decision': 'Block IP recommended',
            'reasoning': 'High confidence credential compromise with privilege escalation'
        })
    
    # Parse actions
    actions = []
    for action in action_logs:
        actions.append({
            'description': action.get('message', 'Action executed'),
            'status': action.get('status', 'unknown'),
            'time': action.get('timestamp', '')[:19]
        })
    
    # Calculate stats
    blocked_ips = len([a for a in action_logs if a.get('action') == 'block_ip' and a.get('status') == 'success'])
    
    return jsonify({
        'stats': {
            'total_incidents': len(incidents),
            'active_alerts': len([i for i in incidents if i['severity'] in ['high', 'critical']]),
            'blocked_ips': blocked_ips
        },
        'incidents': incidents[-10:],  # Last 10
        'timeline': timeline[-15:],     # Last 15
        'decisions': decisions,
        'actions': actions[-10:]        # Last 10
    })

if __name__ == '__main__':
    print("📊 Dashboard starting on port 80...")
    app.run(host='0.0.0.0', port=80)
