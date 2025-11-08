#!/bin/bash

# 1. Generate Certificate Authority (CA) private key
openssl genrsa -out ca.key 2048

# 2. Create the root CA certificate
openssl req -new -x509 -days 365 -key ca.key \
  -subj "/C=US/ST=TEXAS/L=WOODLANDS/O=DEV/OU=LOL/CN=My Local Dev CA" \
  -out ca.crt

# 3. Generate the server's private key and CSR (Certificate Signing Request)
# Using your specific host as the CN
openssl req -newkey rsa:2048 -nodes -keyout server.key \
  -subj "/C=US/ST=TEXAS/L=WOODLANDS/O=DEV/OU=LOL/CN=neo.nullferatu.com" \
  -out server.csr

# 4. Sign the server certificate with your CA
# This is the key change: adding both localhost and your host to the SAN list
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,DNS:neo.nullferatu.com") \
  -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt