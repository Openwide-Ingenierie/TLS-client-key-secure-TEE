#!/bin/bash
./bssl server -accept 55555 -cert ./server.crt -key ./server.key -require-any-client-cert

# Required files :
#   |_ CA.crt    (not yet used to verify client cert)
#   |_ server.crt
#   |_ server.key
