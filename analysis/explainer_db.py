# explainer_db.py - 15 Patterns
EXPLAIN_DB = [
    # Critical Patterns
    {"pattern": "/login", "description": "Authentication endpoint", 
     "tests": ["Test SQL injection: ' OR '1'='1"], "severity": "Critical"},
    
    {"pattern": "/admin", "description": "Admin panel", 
     "tests": ["Try default credentials: admin/admin"], "severity": "Critical"},
    
    {"pattern": "/upload", "description": "File upload", 
     "tests": ["Upload .php file"], "severity": "Critical"},
    
    {"pattern": "/payment", "description": "Payment processing", 
     "tests": ["Test price manipulation"], "severity": "Critical"},
    
    {"pattern": "/reset-password", "description": "Password reset", 
     "tests": ["Test token guessing"], "severity": "Critical"},
    
    # High Severity
    {"pattern": "/api/", "description": "API endpoint", 
     "tests": ["Test without authentication"], "severity": "High"},
    
    {"pattern": "/register", "description": "User registration", 
     "tests": ["Test username enumeration"], "severity": "High"},
    
    {"pattern": "/token", "description": "Token endpoint", 
     "tests": ["Test JWT weakness"], "severity": "High"},
    
    {"pattern": "/cart", "description": "Shopping cart", 
     "tests": ["Test negative pricing"], "severity": "High"},
    
    {"pattern": "?id=", "description": "ID parameter", 
     "tests": ["Change id to access others"], "severity": "High"},
    
    # Medium Severity  
    {"pattern": "/search", "description": "Search function", 
     "tests": ["Test XSS: <script>alert(1)</script>"], "severity": "Medium"},
    
    {"pattern": "/json", "description": "JSON endpoint", 
     "tests": ["Check for data exposure"], "severity": "Medium"},
    
    {"pattern": "/profile", "description": "User profile", 
     "tests": ["Test XSS in fields"], "severity": "Medium"},
    
    {"pattern": "/dashboard", "description": "Dashboard", 
     "tests": ["Check for IDOR"], "severity": "Medium"},
    
    {"pattern": "/submit/", "description": "Data submission", 
     "tests": ["Test parameter tampering"], "severity": "Medium"},
]

def get_explanation(hostname, path, method):
    for entry in EXPLAIN_DB:
        if entry["pattern"].lower() in path.lower():
            return entry
    return None