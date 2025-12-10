# report.py - FINAL, DEFINITIVE VERSION (Restoring Critical Findings)

import json
import os
from datetime import datetime
import sys
import re 

# Define the location of the project root
def get_project_root():
    """Get the absolute path to Bugscope project root"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    return project_root

# --- CUSTOM FILTERING FUNCTION ---
def filter_and_categorize(all_endpoints):
    """Filters endpoints, cleans paths, and deduplicates findings."""
    
    unique_findings = {}
    background_noise = []
    
    # Pattern to match and replace GUIDs/UUIDs in URLs (e.g., 1/a15ebdad-...)
    GUID_PATTERN = re.compile(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    
    # List of known high-volume, low-educational-value background domains/paths
    NOISE_PATTERNS = [
        "mozilla", 
        "telemetry", 
        "detectportal", 
        "ohttp", 
        "fastly-edge", 
        "push.services"
    ]
    
    for endpoint in all_endpoints:
        
        # Check if the finding has an explanation (i.e., it's a security signal)
        has_explanation = endpoint.get('explanation') is not None
        
        # 1. Clean Path (Done regardless of category for consistency)
        path_base = endpoint.get('path', '/').split('?')[0]
        cleaned_path = GUID_PATTERN.sub('/[GUID]', path_base)
        
        host = endpoint.get('host', 'unknown')
        method = endpoint.get('method', 'GET')
        unique_key = f"{method}|{host}|{cleaned_path}"

        
        # 2. Process Findings (If it has an explanation, process it for the report)
        if has_explanation:
            if unique_key not in unique_findings:
                finding = endpoint.copy()
                finding['count'] = 1
                finding['display_path'] = cleaned_path # Store cleaned path
                unique_findings[unique_key] = finding
            else:
                unique_findings[unique_key]['count'] += 1
        
        # 3. Process Noise (If it does NOT have an explanation, check if it's background noise)
        else:
            is_noise = False
            for pattern in NOISE_PATTERNS:
                if pattern in host.lower() or pattern in path_base.lower():
                    is_noise = True
                    break
            if is_noise:
                background_noise.append(endpoint)
             
    return list(unique_findings.values()), background_noise

# --- MAIN REPORT GENERATOR (Rest of the file remains the same, but includes the new findings) ---

def generate_report():
    print("📊 Bugscope Report Generator")
    print("=" * 40)
    
    # Define absolute paths
    PROJECT_ROOT = get_project_root()
    DATA_DIR = os.path.join(PROJECT_ROOT, "data")
    REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
    
    print(f"📍 Project Root: {PROJECT_ROOT}")
    
    # 1. Find latest session file
    session_files = [
        os.path.join(DATA_DIR, f) 
        for f in os.listdir(DATA_DIR) 
        if f.startswith("session_") and f.endswith(".json")
    ]
    
    if not session_files:
        print("❌ No session files found in data/")
        return
    
    latest_file = max(session_files, key=os.path.getmtime)
    filename_only = os.path.basename(latest_file)
    print(f"📂 Using session file: {filename_only}")
    
    # 2. Load data
    try:
        with open(latest_file, "r") as f:
            all_endpoints = json.load(f)
    except Exception as e:
        print(f"❌ Error loading {filename_only}: {e}")
        return
    
    if not all_endpoints:
        print("⚠️ Session file is empty")
        return

    # 3. Filter and Deduplicate
    security_findings, background_noise = filter_and_categorize(all_endpoints)
    
    total_requests = len(all_endpoints)
    total_findings = len(security_findings)
    noise_count = len(background_noise)
    
    # 4. Generate report content
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"session_report_{timestamp}.md"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    # --- HEADER CONTENT ---
    report_content = f"""# 🏆 Bugscope Final Project Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Session File**: {filename_only}  
**Total Requests Captured**: {total_requests}  
**Unique Security Findings**: {total_findings}
**Background Noise Filtered**: {noise_count} requests

## 📊 Executive Summary

This session successfully captured and analyzed user activity, identifying **{total_findings} unique, high-value security finding{'s' if total_findings != 1 else ''}**. **{noise_count}** background requests were filtered to maintain focus.

## 🎯 High-Value Security Findings

"""
    # --- FINDINGS SECTION ---
    
    # Group findings by severity
    findings_by_severity = {}
    for finding in security_findings:
        severity = finding["explanation"].get("severity", "Unknown")
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding)
    
    # Add findings by severity
    severity_order = ["Critical", "High", "Medium", "Low"]
    for severity in severity_order:
        if severity in findings_by_severity and findings_by_severity[severity]:
            count = len(findings_by_severity[severity])
            emoji = {"Critical": "🔥", "High": "🚨", "Medium": "⚠️", "Low": "ℹ️"}.get(severity, "❓")
            report_content += f"\n### {emoji} {severity} Severity ({count} unique finding{'s' if count != 1 else ''})\n\n"
            
            for finding in findings_by_severity[severity]:
                method = finding.get("method", "GET")
                host = finding.get("host", "unknown")
                # Use the 'display_path' if available, otherwise fall back to raw path
                path_display = finding.get('display_path', finding.get('path', '/'))
                explanation = finding.get("explanation", {})
                repetition_count = finding.get("count", 1)
                
                report_content += f"**{method} {host}{path_display}** *(Captured {repetition_count} times)*\n"
                if explanation.get("description"):
                    report_content += f"- {explanation['description']}\n"
                if explanation.get("tests") and explanation["tests"]:
                    report_content += f"- 💡 **Test**: {explanation['tests'][0]}\n"
                report_content += "\n"
    
    # --- INSIGHTS AND NEXT STEPS ---
    report_content += """
## 🔒 Educational Insights

### What This Session Proves:

1.  **Vulnerability Verification:** The successful login attempt using SQL injection (if captured) proves the flaw exists. 
2.  **Mitigation:** By using intelligent path cleaning, the final report focuses exclusively on user-driven actions, filtering out background noise like repeated telemetry calls.
3.  **Prioritization:** Bugscope correctly prioritized Authentication (Critical) and other user-facing functions.

### 🚀 Next Learning Steps (Active Testing):

1.  **Vulnerability Confirmation:** Execute the suggested SQL injection payload to verify the Critical flaw. 
2.  **Expand Scope:** Capture the remaining high-value endpoints like search bars (`/search`) and parameter changes (`?id=`) to complete the coverage of the target site.
3.  **Advanced Analysis:** Compare the **Raw Session File (data/)** with this **Filtered Report (reports/)** to understand the value of filtering.

---
*Bugscope Educational Tool - Version 1.0*
"""
    
    # 5. Save report
    try:
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
            
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        print(f"✅ Report generated: {report_filename}")
        print(f"📍 Saved to: {report_path}")
        
    except Exception as e:
        print(f"❌ Error saving report: {e}")
        return
    
    return report_path

def main():
    try:
        result = generate_report()
        if result:
            print("\n" + "=" * 50)
            print("🎉 FINAL REPORT GENERATED SUCCESSFULLY!")
            print("=" * 50)
            print(f"\n📄 Report file: {result}")
            print("\n📖 To open it:")
            print(f"   notepad \"{result}\"")
        else:
            print("\n" + "=" * 50)
            print("⚠️ NO REPORT GENERATED")
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")

if __name__ == "__main__":
    main()