#!/bin/bash
DEMO_DIR=$(pwd)
OPTEE_QEMU=$DEMO_DIR/optee-qemuv8
CXX=$OPTEE_QEMU/toolchains/aarch64/bin/aarch64-linux-gnu-g++
BORINGSSL=$DEMO_DIR/boringssl


# Build client binary
echo Building client...
cd client
$CXX -o client *.cc -Wall \
 -I$BORINGSSL/include/ \
 $BORINGSSL/build_arm/ssl/libssl.a \
 $BORINGSSL/build_arm/crypto/libcrypto.a \
 -I$OPTEE_QEMU/optee_client/public \
 $OPTEE_QEMU/out-br/target/usr/lib/libteec.so \
 -I../ta


cd ..
# Build Trusted App.
echo Building TA...
cd ta
make \
 CROSS_COMPILE=$OPTEE_QEMU/toolchains/aarch64/bin/aarch64-linux-gnu- \
 BINARY=a3a8cd17-4156-41f5-8a66-fe2643a1c93e \
 -f $OPTEE_QEMU/optee_os/out/arm/export-ta_arm64/mk/ta_dev_kit.mk 


cd ..



