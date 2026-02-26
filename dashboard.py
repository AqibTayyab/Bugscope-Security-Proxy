# dashboard.py - Web Interface for Bugscope

from flask import Flask, render_template_string, request
import db_manager

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bugscope Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <meta http-equiv="refresh" content="5"> </head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark mb-4">
    <div class="container-fluid">
        <a class="navbar-brand" href="/">🕷️ Bugscope Admin Dashboard</a>
    </div>
</nav>
<div class="container">
    <div class="row">
        <div class="col-md-3">
            <div class="card">
                <div class="card-header bg-primary text-white">Sessions</div>
                <div class="list-group list-group-flush">
                    {% for s in sessions %}
                    <a href="/?session={{ s['id'] }}" class="list-group-item list-group-item-action {% if active_session == s['id'] %}active{% endif %}">
                        Session #{{ s['id'] }}<br><small>{{ s['start_time'] }}</small>
                    </a>
                    {% endfor %}
                </div>
            </div>
        </div>
        <div class="col-md-9">
            <h4 class="mb-3">🚨 Detected Vulnerabilities</h4>
            {% if vulns %}
            <table class="table table-danger table-striped">
                <thead><tr><th>Sev</th><th>Description</th><th>Test Case</th></tr></thead>
                <tbody>
                    {% for v in vulns %}
                    <tr>
                        <td><strong>{{ v['severity'] }}</strong></td>
                        <td>{{ v['description'] }}</td>
                        <td><code>{{ v['test_case'] }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="alert alert-success">No vulnerabilities detected in this session yet.</div>
            {% endif %}

            <h4 class="mt-4 mb-3">🌐 Live Traffic Log</h4>
            <table class="table table-sm table-hover bg-white">
                <thead><tr><th>Time</th><th>Method</th><th>Host</th><th>Path</th></tr></thead>
                <tbody>
                    {% for t in traffic %}
                    <tr>
                        <td>{{ t['timestamp'].split(' ')[1] }}</td>
                        <td><span class="badge bg-secondary">{{ t['method'] }}</span></td>
                        <td>{{ t['host'] }}</td>
                        <td class="text-break">{{ t['path'] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
</html>
"""

@app.route('/')
def index():
    conn = db_manager.get_connection()
    sessions = conn.execute("SELECT * FROM sessions ORDER BY id DESC").fetchall()
    
    active_session = request.args.get('session')
    if not active_session and sessions:
        active_session = sessions[0]['id'] # Default to latest
    
    traffic = []
    vulns = []
    
    if active_session:
        traffic = conn.execute("SELECT * FROM traffic WHERE session_id=? ORDER BY id DESC LIMIT 50", (active_session,)).fetchall()
        vulns = conn.execute("""
            SELECT v.* FROM vulnerabilities v
            JOIN traffic t ON v.traffic_id = t.id
            WHERE t.session_id = ?
        """, (active_session,)).fetchall()
    
    conn.close()
    return render_template_string(HTML_TEMPLATE, sessions=sessions, active_session=int(active_session) if active_session else 0, traffic=traffic, vulns=vulns)

if __name__ == '__main__':
    print("🚀 Dashboard running at http://127.0.0.1:5000")
    app.run(port=5000, debug=True)