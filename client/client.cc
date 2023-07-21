
#include <stdio.h>
#include <stdlib.h>

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
    printf("    |_ client.key\n");
}

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

    if (!SSL_CTX_use_PrivateKey_file(ctx.get(), "client.key", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Failed to load private key from file.\n");
        return false;
    }


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
