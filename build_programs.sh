#!/bin/bash
DEMO_DIR=$(pwd)
CXX=$DEMO_DIR/optee-qemuv8/toolchains/aarch64/bin/aarch64-linux-gnu-g++
BORINGSSL=$DEMO_DIR/boringssl

# Build client binary
echo Building client...
cd client
$CXX -o client *.cc -Wall \
 -I$BORINGSSL/include/ \
 $BORINGSSL/build_arm/ssl/libssl.a \
 $BORINGSSL/build_arm/crypto/libcrypto.a 


cd ..




