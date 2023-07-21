#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <user_ta_header_defines.h>

/*
 * Called when the instance of the TA is created. This is the first call in the
 * TA.
 */
TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) { DMSG("has been called"); }

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx) {
    DMSG("has been called");
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
    DMSG("has been called");
}

// Creates new RSA key
static TEE_ObjectHandle create_rsa_key(rsa_pkey_t *key) {
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    TEE_Result res =
        TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key->n_s * 8, &obj);
    if (res != TEE_SUCCESS) {
        EMSG("E: TEE_AllocateTransientObject failed");
        TEE_FreeTransientObject(obj);
        return TEE_HANDLE_NULL;
    }

    TEE_Attribute attrs[3];
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, key->n,
                         key->n_s);  // n
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key->e,
                         key->e_s);  // e
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key->d,
                         key->d_s);  // d
    res = TEE_PopulateTransientObject(obj, attrs, 3);
    if (res != TEE_SUCCESS) {
        EMSG("E: TEE_PopulateTransientObject failed");
        TEE_FreeTransientObject(obj);
        return TEE_HANDLE_NULL;
    }
    return obj;
}

// Puts the key to the storage
static TEE_Result install_key(uint32_t param_types, TEE_Param params[4]) {
    TEE_ObjectHandle transient_obj = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistant_obj = TEE_HANDLE_NULL;

    IMSG("Storing a key");
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) {
        EMSG("E: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rsa_pkey_t *key = (rsa_pkey_t *)params[1].memref.buffer;
    if (sizeof(*key) != params[1].memref.size) {
        EMSG("E: wrong size of rsa_pkey_t struct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    transient_obj = create_rsa_key(key);
    if (transient_obj == TEE_HANDLE_NULL) {
        EMSG("E: Can't create transient object");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Create object
    uint8_t client_id[32];  // SHA256
    memcpy(client_id, params[0].memref.buffer,
           params[0].memref.size);  // must be local
    TEE_Result ret = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,           // Private storage
        client_id, sizeof(client_id),  // Object ID and ID length
        TEE_DATA_FLAG_ACCESS_WRITE,    // flags
        transient_obj,                 // RSA key
        NULL, 0,                       // data
        &persistant_obj                // handle
    );
    if (ret) {
        EMSG("E: Create");
        return ret;
    }
    TEE_FreeTransientObject(transient_obj);
    TEE_CloseObject(persistant_obj);
    return TEE_SUCCESS;
}

// Checks if key exists in the storage
static TEE_Result has_key(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    uint8_t client_id[32];  // SHA256
    memcpy(client_id, params[0].memref.buffer,
           params[0].memref.size);  // must be local
    TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, client_id,
                                              params[0].memref.size,
                                              TEE_DATA_FLAG_ACCESS_READ, &obj);
    if (res) {
        EMSG("E: Open 0x%X", res);
        return res;
    }
    TEE_CloseObject(obj);
    return TEE_SUCCESS;
}

// Performs key deletion from the secure storage
static TEE_Result del_key(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    uint8_t client_id[32];  // SHA256
    memcpy(client_id, params[0].memref.buffer,
           params[0].memref.size);  // must be local

    TEE_Result res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, client_id, params[0].memref.size,
        TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
    if (res) {
        EMSG("E: Can't open");
        return res;
    }
    TEE_CloseAndDeletePersistentObject(obj);
    return TEE_SUCCESS;
}

// Performs RSA signing with a key from secure storage
static TEE_Result sign_rsa(uint32_t param_types, TEE_Param params[4]) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_ObjectHandle key = TEE_HANDLE_NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    uint8_t client_id[32];  // SHA256
    memcpy(client_id, params[0].memref.buffer,
           params[0].memref.size);  // must be local
    TEE_Result res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, client_id, 32, TEE_DATA_FLAG_ACCESS_READ, &key);
    if (res) {
        EMSG("E: Can't open");
        return res;
    }

    // perform RSA sigining
    IMSG("RSA signing");
    res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
                                TEE_MODE_SIGN, MAX_RSA_KEY_SIZE * 8);
    if (res) {
        EMSG("E: Can't allocate signature operation");
        return res;
    }
    TEE_SetOperationKey(op, key);
    res = TEE_AsymmetricSignDigest(
        op, NULL, 0, params[1].memref.buffer, params[1].memref.size,
        params[2].memref.buffer, &params[2].memref.size);
    if (res) {
        EMSG("E: Can't sign with RSA key");
        return res;
    }

    TEE_CloseObject(key);
    TEE_FreeOperation(op);
    return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id, uint32_t param_types,
                                      TEE_Param params[4]) {
    (void)&sess_ctx; /* Unused parameter */
    switch (cmd_id) {
        case TA_INSTALL_KEYS:
            return install_key(param_types, params);
        case TA_HAS_KEYS:
            return has_key(param_types, params);
        case TA_DEL_KEYS:
            return del_key(param_types, params);
        case TA_SIGN_RSA:
            return sign_rsa(param_types, params);
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
