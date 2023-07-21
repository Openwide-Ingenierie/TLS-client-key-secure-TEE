#!/bin/bash

# Import keypair
cp client/client.crt qemu_hostfs
cp client/CA.crt qemu_hostfs
cp admin/client.key qemu_hostfs

# Import binaries
cp client/client qemu_hostfs
cp admin/admin qemu_hostfs
cp ta/a3a8cd17-4156-41f5-8a66-fe2643a1c93e.ta qemu_hostfs
