# report.py - SQLITE DATABASE VERSION

import db_manager
import os

def generate_report():
    conn = db_manager.get_connection()
    
    # Get latest session
    session = conn.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT 1").fetchone()
    if not session:
        print("❌ No sessions found in database.")
        return

    session_id = session['id']
    print(f"📊 Generating report for Session #{session_id}...")
    
    vulns = conn.execute("""
        SELECT v.severity, v.description, v.test_case, t.method, t.host, t.path 
        FROM vulnerabilities v
        JOIN traffic t ON v.traffic_id = t.id
        WHERE t.session_id = ?
        ORDER BY CASE v.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 ELSE 3 END
    """, (session_id,)).fetchall()

    report_content = f"""# 🏆 Bugscope Final Report
**Session ID**: {session_id}
**Date**: {session['start_time']}
**Vulnerabilities Found**: {len(vulns)}

## 🚨 Security Findings
"""
    
    if not vulns:
        report_content += "\nNo vulnerabilities detected.\n"
    else:
        for v in vulns:
            icon = {"Critical": "🔥", "High": "🚨", "Medium": "⚠️"}.get(v['severity'], "ℹ️")
            report_content += f"### {icon} {v['severity']}: {v['description']}\n"
            report_content += f"- **Target**: `{v['method']} {v['host']}{v['path']}`\n"
            report_content += f"- **Test**: `{v['test_case']}`\n\n"

    # Save
    if not os.path.exists('reports'): os.makedirs('reports')
    filename = f"reports/Session_{session_id}_Report.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    print(f"✅ Report saved: {filename}")
    conn.close()

if __name__ == "__main__":
    generate_report()