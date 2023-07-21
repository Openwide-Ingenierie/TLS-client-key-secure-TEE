
#include <stdio.h>
#include <stdlib.h>

// TEEC
#include <tee_client_api.h>

// TA
#include <user_ta_header_defines.h>

// BoringSSL
#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
// BoringSSL tool
#include "transport_common.h"

#define CA_CERTIFICATE "CA.crt"
#define CLIENT_CERTIFICATE "client.crt"
#define CLIENT_ID "client"
#define RSA_KEY_SIZE 256  // bytes

static void usage(const char *name) {
    printf("Usage: %s IP:port\n", name);
    printf("\nRequired files :\n");
    printf("    |_ CA.crt\n");
    printf("    |_ client.crt\n");
    printf("\nclient.key must have been previously inserted into the TEE.\n");
}

/**
 *
 * TEE call
 *
 */
enum ssl_private_key_result_t tee_prv_key_sign(SSL *ssl, uint8_t *out,
                                               size_t *out_len, size_t max_out,
                                               uint16_t signature_algorithm,
                                               const uint8_t *in,
                                               size_t in_len) {
    //// Compute client id hash (in value not used here)
    uint8_t client_id_sha256[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(CLIENT_ID, strlen(CLIENT_ID), client_id_sha256, NULL,
                    EVP_sha256(), NULL)) {
        printf("Failed to compute client id hash.\n");
        return ssl_private_key_failure;
    }

    //// Compute signature hash (SHA256)
    uint8_t digest[SHA256_DIGEST_LENGTH];
    if (!EVP_Digest(in, in_len, digest, NULL, EVP_sha256(), NULL)) {
        printf("Failed to compute client id hash.\n");
        return ssl_private_key_failure;
    }

    //// Call Trusted Application
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_UUID;
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed with code 0x%x\n", res);
        return ssl_private_key_failure;
    }
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x\n", res,
               err_origin);
        return ssl_private_key_failure;
    }
    memset(&op, 0, sizeof(op));
    op.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                         TEEC_MEMREF_TEMP_INOUT, TEEC_NONE);
    op.params[0].tmpref.buffer = client_id_sha256;  // client id
    op.params[0].tmpref.size = SHA256_DIGEST_LENGTH;
    op.params[1].tmpref.buffer = digest;  // hashed message to sign
    op.params[1].tmpref.size = SHA256_DIGEST_LENGTH;
    op.params[2].tmpref.buffer = out;  // result
    *out_len = RSA_KEY_SIZE;           // same as bit numbers
    op.params[2].tmpref.size = *out_len;
    res = TEEC_InvokeCommand(&sess, TA_SIGN_RSA, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res,
               err_origin);
        return ssl_private_key_failure;
    }
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return ssl_private_key_success;
}

static const SSL_PRIVATE_KEY_METHOD prv_key_method = {
    .sign = tee_prv_key_sign, .decrypt = 0, .complete = 0};

/**
 * Communication
 */
bool send(SSL *ssl, char *message, size_t message_len) {
    int ssl_ret = SSL_write(ssl, message, static_cast<int>(message_len));
    if (ssl_ret <= 0) {
        int ssl_err = SSL_get_error(ssl, ssl_ret);
        if (ssl_err == SSL_ERROR_WANT_WRITE) {
            return true;
        }
        PrintSSLError(stderr, "Error while writing", ssl_err, ssl_ret);
        return false;
    }
    if (ssl_ret != static_cast<int>(message_len)) {
        fprintf(stderr, "Short write from SSL_write.\n");
        return false;
    }

    return true;
}
bool read(SSL *ssl, char *buffer) {
    int ssl_ret = SSL_read(ssl, buffer, sizeof(buffer));

    if (ssl_ret < 0) {
        int ssl_err = SSL_get_error(ssl, ssl_ret);
        if (ssl_err == SSL_ERROR_WANT_READ) {
            return true;
        }
        PrintSSLError(stderr, "Error while reading", ssl_err, ssl_ret);
        return true;
    } else if (ssl_ret == 0) {
        return true;  // client closed
    }
    buffer[ssl_ret] = '\0';  // Override line break
    return false;
}

///////////////////
// SSL connection
static bool DoConnection(SSL_CTX *ctx, std::string ip_port,
                         bool (*cb)(SSL *ssl, int sock)) {
    int sock = -1;

    if (!Connect(&sock, ip_port)) {
        return false;
    }

    bssl::UniquePtr<BIO> bio(BIO_new_socket(sock, BIO_CLOSE));
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx));

    SSL_set_bio(ssl.get(), bio.get(), bio.get());
    bio.release();

    int ret = SSL_connect(ssl.get());
    if (ret != 1) {
        int ssl_err = SSL_get_error(ssl.get(), ret);
        PrintSSLError(stderr, "Error while connecting", ssl_err, ret);
        return false;
    }

    fprintf(stderr, "Connected.\n");
    bssl::UniquePtr<BIO> bio_stderr(BIO_new_fp(stderr, BIO_NOCLOSE));
    PrintConnectionInfo(bio_stderr.get(), ssl.get());

    return cb(ssl.get(), sock);
}

/**
 * PROGRAM ENTRY POINT
 */
int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 1;
    }

    // Init context
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    if (!SSL_CTX_use_certificate_chain_file(ctx.get(), CLIENT_CERTIFICATE)) {
        fprintf(stderr, "Error loading certificate from file.\n");
        ERR_print_errors_fp(stderr);
    }

    // Enable signing in TEE
    SSL_CTX_set_private_key_method(ctx.get(), &prv_key_method);

    // Enable CA certificate verification
    if (!SSL_CTX_load_verify_locations(ctx.get(), CA_CERTIFICATE, nullptr)) {
        fprintf(stderr, "Failed to load root certificates.\n");
        ERR_print_errors_fp(stderr);
        return false;
    }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

    // Do connection
    return DoConnection(ctx.get(), argv[1], &TransferData);
}
