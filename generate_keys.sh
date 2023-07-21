#!/bin/bash


mkdir CA
cd CA

# Generate CA
echo Generating CA...
openssl req -x509 -days 7300 \
        -newkey rsa:2048 -keyout CA.key \
        -out CA.crt \
        -subj "/C=FR/ST=ARA/L=Grenoble/O=LinuxEmbedded/OU=SECS/CN=Certificate Authority" \
        -noenc

# Generate server key-pair
echo Generating server key-pair...
openssl req -new \
        -newkey rsa:2048 -keyout server.key \
        -out server.csr \
        -subj "/C=FR/ST=ARA/L=Grenoble/O=LinuxEmbedded/OU=SECS/CN=Server" \
        -noenc
openssl x509 -req -days 7300 -in server.csr \
        -CA CA.crt \
        -CAkey CA.key -sha256  \
        -CAcreateserial \
        -out server.crt
rm server.csr

# Generate client key-pair
echo Generating client key-pair...
openssl req -new \
        -newkey rsa:2048 -keyout client.key \
        -out client.csr \
        -subj "/C=FR/ST=ARA/L=Grenoble/O=LinuxEmbedded/OU=SECS/CN=Client" \
        -noenc
openssl x509 -req -days 7300 -in client.csr \
        -CA CA.crt \
        -CAkey CA.key -sha256  \
        -CAcreateserial \
        -out client.crt
rm client.csr

# Distribute files
mv client.key ../admin

cp CA.crt ../client
mv client.crt ../client

cp CA.crt ../server
mv server.crt ../server
mv server.key ../server


