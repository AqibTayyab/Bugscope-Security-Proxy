# main_educational.py - FINAL, ULTIMATE VERSION (Using Requests for All Traffic)

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
import json
import sys
import signal 
from urllib.parse import urlparse 

# Suppress the InsecureRequestWarning because we are intentionally MITM'ing self-signed certs
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ====================================================================
# GLOBAL PATH SETUP (FIXED)
# ====================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) # Bugscope/

DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
CA_CERT_FILE = os.path.join(PROJECT_ROOT, 'certificates', 'ca-cert.pem')
CA_KEY_FILE = os.path.join(PROJECT_ROOT, 'certificates', 'ca-key.pem')

# Config (Listen on ALL interfaces to allow "Fake Stranger" access)
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 8080

# Fix import path for external run
sys.path.append(PROJECT_ROOT)

# Import from analysis directory
try:
    from analysis.explainer_db import EXPLAIN_DB, get_explanation
    print("✅ Loaded vulnerability database")
except ImportError as e:
    print(f"❌ Error loading explainer_db: {e}")
    EXPLAIN_DB = []
    def get_explanation(hostname, path, method):
        return None

# Verify and Load CA
try:
    with open(CA_CERT_FILE, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY_FILE, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    print("✅ CA certificates loaded successfully")
except Exception as e:
    print(f"❌ Error loading certificates: {e}")

intercepted_endpoints = []
certificate_cache = {}

# ====================================================================
# CORE FUNCTIONS
# ====================================================================

def save_session():
    """Save session data (Uses globally defined DATA_DIR)"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    if not intercepted_endpoints:
        print("⚠️ No endpoints captured, nothing to save")
        return
    
    filename = os.path.join(DATA_DIR, f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(intercepted_endpoints, f, indent=2)
        
        endpoints_with_explanations = len([e for e in intercepted_endpoints if e.get('explanation')])
        print(f"💾 Session saved: {len(intercepted_endpoints)} endpoints ({endpoints_with_explanations} with explanations)")
        print(f"📁 File saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving session: {e}")


def generate_cert(hostname):
    """Generate certificate for hostname with caching"""
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
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        certificate_cache[hostname] = (cert_pem, key_pem)
        return cert_pem, key_pem
        
    except Exception as e:
        print(f"❌ Certificate generation error: {e}")
        raise


def handle_https_tunnel(client_socket, hostname):
    """Handle HTTPS with improved explanations (Uses requests)"""
    try:
        cert_pem, key_pem = generate_cert(hostname)
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
            cert_file.write(cert_pem + key_pem)
            temp_cert_path = cert_file.name
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(temp_cert_path)
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            
            request_data = b""
            ssl_socket.settimeout(2.0)
            
            try:
                chunk = ssl_socket.recv(4096)
                request_data = chunk
            except socket.timeout:
                pass
            
            if request_data:
                request_text = request_data.decode('utf-8', errors='ignore')
                lines = request_text.split('\n')
                
                if lines and lines[0].strip():
                    first_line = lines[0].strip()
                    method = first_line.split(' ')[0] if ' ' in first_line else 'UNKNOWN'
                    path = first_line.split(' ')[1] if ' ' in first_line else '/'
                    
                    print(f"🔓 [HTTPS] {method} {hostname}{path}")
                    
                    explanation = get_explanation(hostname, path, method)
                    if explanation:
                        print(f"   📚 {explanation['description']}")
                        if explanation.get('tests'):
                            print(f"   💡 Try: {explanation['tests'][0]}")
                        if explanation.get('severity'):
                            severity_icon = {
                                'Critical': '🔥',
                                'High': '🚨',
                                'Medium': '⚠️',
                                'Low': 'ℹ️'
                            }.get(explanation['severity'], '📊')
                            print(f"   {severity_icon} Severity: {explanation['severity']}")
                    else:
                        print(f"   ℹ️  General web traffic")
                    
                    endpoint = {
                        'method': method,
                        'host': hostname,
                        'path': path,
                        'timestamp': datetime.now().isoformat(),
                        'explanation': explanation
                    }
                    intercepted_endpoints.append(endpoint)
                    
                    try:
                        # Forwarding using requests
                        url = f"https://{hostname}{path}"
                        response = requests.request(method, url, data=request_data, timeout=5, verify=False) 
                        
                        # Send headers and content back to client
                        response_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
                        ssl_socket.send(response_line.encode())
                        
                        for header, value in response.headers.items():
                            ssl_socket.send(f"{header}: {value}\r\n".encode())
                        
                        ssl_socket.send(b"\r\n")
                        ssl_socket.send(response.content)
                        
                        print(f"   ✅ Response: {response.status_code}")
                        
                    except Exception as e:
                        error_msg = f"HTTP/1.1 502 Bad Gateway\r\n\r\nError: {e}"
                        ssl_socket.send(error_msg.encode())
            
            ssl_socket.close()
            
        finally:
            os.unlink(temp_cert_path)
            
    except Exception as e:
        if 'SSLError' in str(e) or 'EOF' in str(e):
             pass # Connection Reset/Socket Error are common/harmless here
        else:
             pass # Silently drop connection if external service is unstable


def handle_client(client_socket):
    """Handle client connection (FIXED: Using Requests for robust HTTP forwarding)"""
    try:
        client_socket.settimeout(5.0)
        request_bytes = client_socket.recv(4096)
        if not request_bytes:
            return

        request = request_bytes.decode('latin-1')
        first_line = request.split('\n')[0].strip()

        if first_line.startswith('CONNECT'):
            # HTTPS Request: Handled by handle_https_tunnel
            hostname = first_line.split(' ')[1].split(':')[0]
            print(f"🔒 [TUNNEL] Establishing HTTPS to: {hostname}")
            
            client_socket.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            handle_https_tunnel(client_socket, hostname)
            
        else:
            # HTTP Request: Now properly forwarded via requests
            
            parts = first_line.split(' ')
            if len(parts) < 2:
                client_socket.close()
                return

            method = parts[0]
            path_with_protocol = parts[1] 

            url_parts = urlparse(path_with_protocol)
            hostname = url_parts.netloc
            path = url_parts.path + ("?" + url_parts.query if url_parts.query else "")

            if not hostname:
                # Fallback using host header
                for line in request.split('\n'):
                    if line.lower().startswith('host:'):
                        hostname = line.split(': ')[1].strip()
                        break
                if not hostname:
                    client_socket.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    return
            
            print(f"🌐 [HTTP] {method} {hostname}{path}")

            # Get educational analysis (for display and logging)
            explanation = get_explanation(hostname, path, method)
            if explanation:
                print(f"   📚 {explanation['description']}")
                print(f"   💡 Try: {explanation['tests'][0]}")

            # Log endpoint
            endpoint = {
                'method': method,
                'host': hostname,
                'path': path_with_protocol,
                'timestamp': datetime.now().isoformat(),
                'explanation': explanation
            }
            intercepted_endpoints.append(endpoint)
            
            # --- FORWARDING REQUEST (CRITICAL FIX using requests) ---
            
            try:
                # Construct the full, correct URL for requests
                url = f"http://{hostname}{path}"
                
                # Forward using requests—far more stable than raw sockets
                # Data=request_bytes ensures POST bodies are forwarded
                response = requests.request(method, url, data=request_bytes, timeout=5)
                
                # Send response back to client socket
                response_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
                client_socket.send(response_line.encode())
                
                # Forward headers
                for header, value in response.headers.items():
                    client_socket.send(f"{header}: {value}\r\n".encode())
                
                client_socket.send(b"\r\n")
                client_socket.send(response.content)
                
                print(f"   ✅ Forwarded and returned response: {response.status_code}")
                
            except requests.exceptions.Timeout:
                print(f"❌ Forwarding Error: Request timed out via requests.")
                client_socket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
            except Exception as e:
                # Catch connection failures, DNS errors, etc.
                print(f"❌ Forwarding Error: {e}")
                client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")

    except Exception as e:
        if 'timed out' in str(e):
            pass # Ignore simple timeouts
        else:
            pass # Ignore other simple socket exceptions
    finally:
        try:
            client_socket.close()
        except:
            pass


# ====================================================================
# CTRL+C SIGNAL HANDLER (FIXED)
# ====================================================================

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global server 
    print("\n" + "="*50)
    print("🛑 Received shutdown signal (Ctrl+C)...")
    print("Saving session and cleaning up...")
    print("="*50)
    
    # Save session data 
    save_session()
    
    # Close server socket
    if 'server' in globals():
        try:
            server.close()
            print("✅ Server socket closed")
        except:
            pass
    
    # Exit cleanly
    print("\n🎯 Bugscope stopped successfully")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

# ====================================================================
# START PROXY SERVER
# ====================================================================

try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(10)
    
    print("\n" + "="*50)
    print("✅ [READY] Bugscope Educational MITM Proxy")
    print("="*50)
    print("\n🎓 Final fix for loading websites applied!")
    print("🌐 Proxy: 0.0.0.0:8080 (Use your IP in Firefox)")
    print("🔥 Critical patterns: /login, /admin, /upload, /payment")
    print("📚 Press Ctrl+C to save session and exit")
    print("="*50 + "\n")
    
    while True:
        try:
            client_socket, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.daemon = True 
            client_thread.start()
        except Exception as e:
            if 'socket operation on non-socket' in str(e) or 'Bad file descriptor' in str(e):
                break
            # Ignore accept errors from sockets that close unexpectedly
            pass
            
except KeyboardInterrupt:
    pass 
    
except Exception as e:
    print(f"❌ Fatal Server error (main block): {e}")
    signal_handler(signal.SIGINT, None)

finally:
    if 'server' in globals():
        try:
            server.close()
        except:
            pass