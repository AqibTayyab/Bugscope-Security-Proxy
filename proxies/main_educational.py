# main_educational.py - FIXED VERSION (No Hangs + Noise Filter)

import socket
import ssl
import threading
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
import tempfile
from datetime import datetime, timezone, timedelta
import sys
import signal 
from urllib.parse import urlparse 

# Suppress warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ====================================================================
# GLOBAL PATH SETUP
# ====================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) 
sys.path.append(PROJECT_ROOT)

try:
    import db_manager
except ImportError:
    sys.path.append(SCRIPT_DIR)
    import db_manager

DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
CA_CERT_FILE = os.path.join(PROJECT_ROOT, 'certificates', 'ca-cert.pem')
CA_KEY_FILE = os.path.join(PROJECT_ROOT, 'certificates', 'ca-key.pem')

PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8080

# NOISE FILTER: Domains to IGNORE completely
IGNORED_DOMAINS = [
    "mozilla", "firefox", "google", "gstatic", "googleapis", 
    "telemetry", "push.services", "detectportal", "bing", "microsoft",
    "acunetix", "visualwebsiteoptimizer", "geojs", "splide"
]

try:
    from analysis.explainer_db import get_explanation
    print("✅ Loaded vulnerability database")
except ImportError:
    try:
        from explainer_db import get_explanation
        print("✅ Loaded vulnerability database (local)")
    except ImportError:
        def get_explanation(h, p, m): return None

try:
    with open(CA_CERT_FILE, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY_FILE, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    print("✅ CA certificates loaded successfully")
except Exception as e:
    print(f"❌ Error loading certificates: {e}")
    sys.exit(1)

certificate_cache = {}
CURRENT_SESSION_ID = None 

# ====================================================================
# CORE FUNCTIONS
# ====================================================================

def is_ignored_host(hostname):
    """Check if host is background noise"""
    if not hostname: return True
    for domain in IGNORED_DOMAINS:
        if domain in hostname.lower():
            return True
    return False

def generate_cert(hostname):
    if hostname in certificate_cache:
        return certificate_cache[hostname]
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
            .sign(ca_key, hashes.SHA256()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        certificate_cache[hostname] = (cert_pem, key_pem)
        return cert_pem, key_pem
    except Exception as e:
        print(f"❌ Certificate generation error: {e}")
        raise

def process_and_log(method, hostname, path):
    """Analyzes request and logs to SQL Database"""
    if CURRENT_SESSION_ID is None: return
    
    # FILTER: Don't log Mozilla/Google noise to DB
    if is_ignored_host(hostname):
        return

    try:
        traffic_id = db_manager.log_traffic(CURRENT_SESSION_ID, method, hostname, path)
        explanation = get_explanation(hostname, path, method)
        
        if explanation:
            print(f"   🔥 [VULN] {explanation['severity']}: {explanation['description']}")
            test_str = explanation['tests'][0] if explanation.get('tests') else "Manual check required"
            db_manager.log_vulnerability(
                traffic_id=traffic_id,
                severity=explanation['severity'],
                description=explanation['description'],
                test_case=test_str
            )
    except Exception as e:
        print(f"❌ DB Log Error: {e}")

def parse_raw_request(raw_data):
    """Splits raw bytes into Headers (dict) and Body (bytes)"""
    try:
        parts = raw_data.split(b'\r\n\r\n', 1)
        header_part = parts[0].decode('latin-1')
        body = parts[1] if len(parts) > 1 else b""
        
        headers = {}
        lines = header_part.split('\r\n')
        # Skip first line (GET / HTTP/1.1)
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                # Filter problematic headers for forwarding
                if key.lower() not in ['host', 'content-length', 'content-encoding', 'transfer-encoding']:
                    headers[key] = value
        return headers, body
    except Exception:
        return {}, raw_data

def handle_https_tunnel(client_socket, hostname):
    try:
        cert_pem, key_pem = generate_cert(hostname)
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
            cert_file.write(cert_pem + key_pem)
            temp_cert_path = cert_file.name
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(temp_cert_path)
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            ssl_socket.settimeout(1.0) # Lower timeout for easier Ctrl+C
            
            try:
                request_data = ssl_socket.recv(8192) # Increased buffer
            except socket.timeout:
                request_data = b""
            
            if request_data:
                request_text = request_data.decode('utf-8', errors='ignore')
                first_line = request_text.split('\n')[0].strip()
                if first_line:
                    method = first_line.split(' ')[0]
                    path = first_line.split(' ')[1] if ' ' in first_line else '/'
                    
                    if not is_ignored_host(hostname):
                        print(f"🔒 [HTTPS] {method} {hostname}{path}")
                    
                    process_and_log(method, hostname, path)

                    # FIX: Separate Headers and Body
                    headers, body = parse_raw_request(request_data)
                    url = f"https://{hostname}{path}"
                    
                    try:
                        response = requests.request(method, url, headers=headers, data=body, timeout=5, verify=False, allow_redirects=False)
                        
                        ssl_socket.send(f"HTTP/1.1 {response.status_code} {response.reason}\r\n".encode())
                        for h, v in response.headers.items():
                            if h.lower() not in ['transfer-encoding', 'content-encoding']:
                                ssl_socket.send(f"{h}: {v}\r\n".encode())
                        ssl_socket.send(b"\r\n")
                        ssl_socket.send(response.content)
                    except Exception:
                        ssl_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            ssl_socket.close()
        finally:
            if os.path.exists(temp_cert_path):
                try: os.unlink(temp_cert_path)
                except: pass
    except Exception:
        pass

def handle_client(client_socket):
    try:
        client_socket.settimeout(1.0) # Lower timeout
        try:
            request_bytes = client_socket.recv(8192)
        except socket.timeout:
            return
            
        if not request_bytes: return
        request = request_bytes.decode('latin-1')
        first_line = request.split('\n')[0].strip()

        if first_line.startswith('CONNECT'):
            hostname = first_line.split(' ')[1].split(':')[0]
            client_socket.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            handle_https_tunnel(client_socket, hostname)
        else:
            parts = first_line.split(' ')
            if len(parts) < 2: return
            method, path_url = parts[0], parts[1]
            url_parts = urlparse(path_url)
            hostname = url_parts.netloc
            path = url_parts.path + ("?" + url_parts.query if url_parts.query else "")
            
            if not hostname:
                for line in request.split('\n'):
                    if line.lower().startswith('host:'):
                        hostname = line.split(': ')[1].strip()
                        break
            
            if not is_ignored_host(hostname):
                print(f"🌐 [HTTP] {method} {hostname}{path}")
            
            process_and_log(method, hostname, path)

            # FIX: Separate Headers and Body
            headers, body = parse_raw_request(request_bytes)
            try:
                url = f"http://{hostname}{path}"
                response = requests.request(method, url, headers=headers, data=body, timeout=5, allow_redirects=False)
                
                client_socket.send(f"HTTP/1.1 {response.status_code} {response.reason}\r\n".encode())
                for h, v in response.headers.items():
                    if h.lower() not in ['transfer-encoding', 'content-encoding']:
                        client_socket.send(f"{h}: {v}\r\n".encode())
                client_socket.send(b"\r\n")
                client_socket.send(response.content)
            except Exception:
                client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    except Exception:
        pass
    finally:
        client_socket.close()

def signal_handler(sig, frame):
    print("\n Shutting down Bugscope...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    db_manager.init_db()
    CURRENT_SESSION_ID = db_manager.create_session(target_host="Mixed/Lab")
    print(f"✅ Session Started (ID: {CURRENT_SESSION_ID})")

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(20)
        print(f"🚀 Bugscope Running on {PROXY_HOST}:{PROXY_PORT}")
        print("📂 Logging to: data/bugscope.db")
        print("🔇 Ignoring noise from: Mozilla, Google, Microsoft")
        while True:
            try:
                server.settimeout(1.0) # Check for Ctrl+C every second
                client_sock, _ = server.accept()
                threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
    except Exception as e:
        print(f"❌ Startup Error: {e}")