# mitm_proxy.py - Simple MITM Proxy for Bugscope
import socket
import ssl
import threading
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from datetime import datetime, timedelta

# Config
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080
CA_CERT_FILE = 'Certificates/ca-cert.pem'
CA_KEY_FILE = 'Certificates/ca-key.pem'

print("🔧 [Bugscope MITM Proxy] Starting on port 8080...")

# Load CA
with open(CA_CERT_FILE, 'rb') as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())
with open(CA_KEY_FILE, 'rb') as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

def generate_cert(hostname):
    """Generate certificate for hostname signed by our CA"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .sign(ca_key, hashes.SHA256()))
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem, key_pem

def handle_client(client_socket):
    try:
        request = client_socket.recv(4096).decode('latin-1')
        first_line = request.split('\n')[0]
        
        if first_line.startswith('CONNECT'):
            hostname = first_line.split(' ')[1].split(':')[0]
            print(f"🔒 [HTTPS] Intercepting: {hostname}")
            
            client_socket.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            
            cert_pem, key_pem = generate_cert(hostname)
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=(cert_pem, key_pem))
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            
            http_request = ssl_socket.recv(8192).decode('utf-8', errors='ignore')
            if http_request:
                first_http_line = http_request.split('\n')[0]
                print(f"🔓 [DECRYPTED] {first_http_line}")
            
            ssl_socket.close()
        else:
            print(f"🌐 [HTTP] {first_line}")
            client_socket.close()
            
    except Exception as e:
        print(f"❌ [ERROR] {e}")

# Start proxy
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((PROXY_HOST, PROXY_PORT))
server.listen(5)

print("✅ [READY] MITM Proxy running! Configure Firefox to use 127.0.0.1:8080")

try:
    while True:
        client_socket, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.daemon = True
        client_thread.start()
except KeyboardInterrupt:
    print("\n🛑 [SHUTDOWN] Proxy stopped")
    server.close()