#!/bin/bash

openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/C=US/ST=TEXAS/L=WOODLANDS/O=DEV/OU=LOL/CN=*.nilnilnil.nil/emailAddress=you@okay.com" -out ca.crt
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=US/ST=TEXAS/L=WOODLANDS/O=DEV/OU=LOL/CN=*.nilnilnil.nil/emailAddress=you@okay.com" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt