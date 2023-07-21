#!/bin/bash
DEMO_DIR=$(pwd)

# Build QEMU
mkdir optee-qemuv8
cd optee-qemuv8
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync
cd build
make toolchains 
make QEMU_VIRTFS_AUTOMOUNT=y

cd ../..
# Build BoringSSL for host
git clone https://github.com/google/boringssl
cd boringssl
mkdir build
cd build
cmake ..
make

cd ..
# Build BoringSSL for ARMv8
mkdir build_arm
cd build_arm
CC=$DEMO_DIR/optee-qemuv8/toolchains/aarch64/bin/aarch64-linux-gnu-gcc CXX=$DEMO_DIR/optee-qemuv8/toolchains/aarch64/bin/aarch64-linux-gnu-g++ cmake ..
make

cd ../..
# Import bssl tool used as server
cp boringssl/build/tool/bssl server

# Import needed bssl tool sources for client
cp boringssl/tool/transport_common.* boringssl/tool/internal.h boringssl/tool/fd.cc client

