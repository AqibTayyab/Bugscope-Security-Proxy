@echo off
cd /d "D:\Aqib\Projects\Project Python\2. Beginner Intercepting Proxy & Explainer"
echo Generating CA private key...
"D:\Software\OpenSSL-Win64\bin\openssl.exe" genrsa -out Certificates\ca-key.pem 2048

echo Generating CA certificate...
"D:\Software\OpenSSL-Win64\bin\openssl.exe" req -new -x509 -days 365 -key Certificates\ca-key.pem -out Certificates\ca-cert.pem -subj "/CN=Bugscope Proxy CA/O=Bugscope/C=US" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

echo Creating PKCS12 file for browser...
"D:\Software\OpenSSL-Win64\bin\openssl.exe" pkcs12 -export -out Certificates\ca-cert.p12 -in Certificates\ca-cert.pem -inkey Certificates\ca-key.pem -passout pass:1234

echo Done! Certificates generated in Certificates\ folder
pause
