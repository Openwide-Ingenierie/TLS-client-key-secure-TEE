
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TEEC
#include <tee_client_api.h>

// TA
#include <user_ta_header_defines.h>

// BoringSSL
#include <openssl/evp.h>
#include <openssl/pem.h>

#define CLIENT_ID "client"
#define CLIENT_KEY CLIENT_ID ".key"

static void usage(const char *name) {
    printf("Usage: %s put|has|del\n", name);
    printf("\nRequired file :\n");
    printf("    |_ client.key\n");
}

/**
 * PROGRAM ENTRY POINT
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    //// Prepare Trusted Application
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_UUID;
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        return 1;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x\n", res,
               err_origin);
        return 1;
    }
    memset(&op, 0, sizeof(op));

    //// Compute client id hash
    uint8_t client_id_sha256[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(CLIENT_ID, strlen(CLIENT_ID), client_id_sha256, NULL,
                    EVP_sha256(), NULL)) {
        printf("Failed to compute hash.\n");
        return 1;
    }

    if (!strncmp(argv[1], "put", 3)) {  //// TA_INSTALL_KEYS
        EVP_PKEY *pkey;                 // Read .key file
        if (!(pkey = PEM_read_PrivateKey(fopen(CLIENT_KEY, "r"), NULL, NULL,
                                         NULL))) {
            printf("Failed to load private key in file : %s\n", CLIENT_KEY);
            return 1;
        }
        RSA *rsa_pkey = EVP_PKEY_get0_RSA(pkey);
        if (!rsa_pkey) {
            printf("Can't read RSA key.\n");
            return 1;
        }
        // Format key
        const BIGNUM *bnn, *bne, *bnd = NULL;
        RSA_get0_key(rsa_pkey, &bnn, &bne, &bnd);
        rsa_pkey_t key;
        BN_bn2bin(bnn, key.n);  // modulus
        key.n_s = BN_num_bytes(bnn);
        BN_bn2bin(bne, key.e);  // public exponent
        key.e_s = BN_num_bytes(bne);
        BN_bn2bin(bnd, key.d);  // private exponent
        key.d_s = BN_num_bytes(bnd);

        printf("Installing key with ID '%s' ...\n", CLIENT_ID);
        op.paramTypes =
            TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                             TEEC_NONE, TEEC_NONE);  // ID, private key
        op.params[0].tmpref.buffer = client_id_sha256;
        op.params[0].tmpref.size = SHA256_DIGEST_LENGTH;  //(32)
        op.params[1].tmpref.buffer = &key;
        op.params[1].tmpref.size = sizeof(key);
        res = TEEC_InvokeCommand(&sess, TA_INSTALL_KEYS, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("Key with ID '%s' is installed.\n", CLIENT_ID);
        } else if (res == TEEC_ERROR_ACCESS_CONFLICT) {
            printf("This key is already installed !\n");
        } else {
            printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
                   res, err_origin);
            return 1;
        }

    } else if (!strncmp(argv[1], "has", 3)) {  //// TA_HAS_KEYS
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                         TEEC_NONE, TEEC_NONE);  // ID
        op.params[0].tmpref.buffer = client_id_sha256;
        op.params[0].tmpref.size = SHA256_DIGEST_LENGTH;  //(32)
        res = TEEC_InvokeCommand(&sess, TA_HAS_KEYS, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("Key with ID '%s' is already installed.\n", CLIENT_ID);
        } else if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
            printf("Key with ID '%s' is not installed.\n", CLIENT_ID);
        } else {
            printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
                   res, err_origin);
            return 1;
        }
    } else if (!strncmp(argv[1], "del", 3)) {  //// TA_DEL_KEYS
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                                         TEEC_NONE, TEEC_NONE);  // ID
        op.params[0].tmpref.buffer = client_id_sha256;
        op.params[0].tmpref.size = SHA256_DIGEST_LENGTH;  //(32)
        res = TEEC_InvokeCommand(&sess, TA_DEL_KEYS, &op, &err_origin);
        if (res == TEEC_SUCCESS) {
            printf("Key with ID '%s' was deleted.\n", CLIENT_ID);
        } else {
            printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
                   res, err_origin);
            return 1;
        }
    } else {
        usage(argv[0]);
        return 1;
    }

    // Close TA
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return 0;
}