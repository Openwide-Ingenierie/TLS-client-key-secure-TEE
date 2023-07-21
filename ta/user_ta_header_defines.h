/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H
#include <stdint.h>

/* TA UUID*/
#define TA_UUID                                            \
    {                                                      \
        0xa3a8cd17, 0x4156, 0x41f5, {                      \
            0x8a, 0x66, 0xfe, 0x26, 0x43, 0xa1, 0xc9, 0x3e \
        }                                                  \
    }

/* The function IDs implemented in this TA */
#define TA_INSTALL_KEYS 0
#define TA_HAS_KEYS 1
#define TA_DEL_KEYS 2
#define TA_SIGN_RSA 4
/* Structure used as parameter */
#define MAX_RSA_KEY_SIZE 512  // bytes
typedef struct {
    uint8_t n[MAX_RSA_KEY_SIZE];
    uint32_t n_s;
    uint8_t e[MAX_RSA_KEY_SIZE];
    uint32_t e_s;
    uint8_t d[MAX_RSA_KEY_SIZE];
    uint32_t d_s;
} rsa_pkey_t;

/*
 * TA properties: multi-instance TA, no specific attribute
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE (64 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE (64 * 1024)

/* Extra properties (give a version id and a string name) */
#define TA_CURRENT_TA_EXT_PROPERTIES                                         \
    {"gp.ta.description", USER_TA_PROP_TYPE_STRING,                          \
     "TLS client private key signature"},                                    \
    {                                                                        \
        "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t) { 0x0010 } \
    }

#endif /* USER_TA_HEADER_DEFINES_H */
