# Demonstration : TLS secure key into OP-TEE
**➡️ Please first read this Linux Embedded article : \<todo_insert_link\>**

<img src="demo.png"  width="400">

This demonstration is inspired by [this article](https://www.amongbytes.com/post/201904-tee-sign-delegator/) from Krys Kwiatkowski.\
This version aims to show how to implement a TLS client-server with BoringSSL on QEMU ARMv8 emulator. Then how to delegate to OP-TEE the signing of the client's private RSA key.



## Build demo

### Initial setup
This demonstration needs the official OP-TEE QEMUv8 emulator and BoringSSL built for host PC and ARMv8 target. Just execute the following script (may take an hour):
```bash
./initial_setup.sh
```
It also prepare needed files for TLS server and client.

### Generate key-pairs
The following script will generate all necessary key-pairs :
```bash
./generate_keys.sh
```

### Build 
Several ARMv8 binaries are needed :
- the client program
- the trusted application (TA)
- the admin program

Then please execute the following script :
```bash
./build_programs.sh
```


## Run demonstration

### Setup the system
Run the following script to import all needed files into QEMU :
```bash
./qemu_import.sh
```

Then start the QEMU environment in a terminal :
```bash
cd optee-qemuv8/build
make \
 QEMU_VIRTFS_ENABLE=y \
 QEMU_VIRTFS_HOST_DIR=$PWD/../../qemu_hostfs/ \
 run-only

(qemu) c
```
`c` command will popup two terminals, please connect to the normal world Linux with `root` user (no password).

In the normal world install the encrypted Trusted Application :
```bash
cd /mnt/host
mv a3a8cd17-4156-41f5-8a66-fe2643a1c93e.ta /lib/optee_armtz
```


### Install private key
As the administrator you can install the client private key into the TEE :
```bash
./admin put
```

Then the administrator leave the device !
```bash
rm admin client.key
```


### Test the client
On computer side launch the server (port 55555) in a terminal :
```bash
cd server
ifconfig
./server.sh
```

Back into QEMU normal world you can now try the client :
```bash
cd /mnt/host
./client <IP>:55555
```
