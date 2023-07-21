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

// Puts the key to the storage
static TEE_Result install_key(uint32_t param_types, TEE_Param params[4]) {
    return TEE_SUCCESS;
}

// Checks if key exists in the storage
static TEE_Result has_key(uint32_t param_types, TEE_Param params[4]) {
    return TEE_SUCCESS;
}

// Performs key deletion from the secure storage
static TEE_Result del_key(uint32_t param_types, TEE_Param params[4]) {
    return TEE_SUCCESS;
}

// Performs RSA signing with a key from secure storage
static TEE_Result sign_rsa(uint32_t param_types, TEE_Param params[4]) {
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
