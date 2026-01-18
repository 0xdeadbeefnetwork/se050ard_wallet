/*
 * SE050 Hardware Wallet C Library - Implementation
 * 
 * Uses NXP middleware's ex_sss_boot helpers for proper SCP03 setup.
 *
 * Copyright 2025 _SiCk @ afflicted.sh
 * SPDX-License-Identifier: MIT
 */

#include "se050_wallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <glob.h>
#include <unistd.h>

/* NXP Plug & Trust Middleware headers */
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU.h>
#include <ex_sss_boot.h>
#include <nxLog_App.h>

/* mbedtls for EC point derivation */
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

/* ============================================================================
 * Internal State
 * ============================================================================ */

#define SE050_WALLET_VERSION "1.0.0"
#define MAX_SIGNATURE_LEN 72
#define SECP256K1_PUBKEY_LEN 65
#define SECP256K1_PRIVKEY_LEN 32
#define SHA256_HASH_LEN 32
#define UID_MAX_LEN 18

/* secp256k1 curve order for low-S normalization */
static const uint8_t SECP256K1_ORDER[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

static const uint8_t SECP256K1_HALF_ORDER[] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
    0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
};

/* Session context - use middleware's boot context */
static struct {
    bool connected;
    bool debug;
    ex_sss_boot_ctx_t boot_ctx;
    char port[256];
    char scp_key_file[512];
} g_ctx = {0};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static void debug_log(const char *fmt, ...) {
    if (g_ctx.debug) {
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "[SE050] ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        fflush(stderr);
        va_end(args);
    }
}

/**
 * Auto-detect SE050 serial port
 */
static const char *detect_port(void) {
    static char port_buf[64];
    glob_t glob_result;
    
    if (glob("/dev/ttyACM*", 0, NULL, &glob_result) == 0 && glob_result.gl_pathc > 0) {
        strncpy(port_buf, glob_result.gl_pathv[0], sizeof(port_buf) - 1);
        globfree(&glob_result);
        return port_buf;
    }
    globfree(&glob_result);
    
    if (glob("/dev/ttyUSB*", 0, NULL, &glob_result) == 0 && glob_result.gl_pathc > 0) {
        strncpy(port_buf, glob_result.gl_pathv[0], sizeof(port_buf) - 1);
        globfree(&glob_result);
        return port_buf;
    }
    globfree(&glob_result);
    
    return NULL;
}

static int compare_be(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void subtract_be(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t len) {
    int borrow = 0;
    for (int i = len - 1; i >= 0; i--) {
        int diff = a[i] - b[i] - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = (uint8_t)diff;
    }
}

static int normalize_signature(uint8_t *sig, size_t *sig_len) {
    if (*sig_len < 8 || sig[0] != 0x30) {
        return SE050_ERR_INVALID_PARAM;
    }
    
    size_t total_len = sig[1];
    if (total_len + 2 > *sig_len) {
        return SE050_ERR_INVALID_PARAM;
    }
    
    if (sig[2] != 0x02) return SE050_ERR_INVALID_PARAM;
    size_t r_len = sig[3];
    const uint8_t *r_ptr = &sig[4];
    
    size_t s_offset = 4 + r_len;
    if (sig[s_offset] != 0x02) return SE050_ERR_INVALID_PARAM;
    size_t s_len = sig[s_offset + 1];
    uint8_t *s_ptr = &sig[s_offset + 2];
    
    const uint8_t *s_val = s_ptr;
    size_t s_val_len = s_len;
    while (s_val_len > 32 && *s_val == 0x00) {
        s_val++;
        s_val_len--;
    }
    
    uint8_t s_32[32] = {0};
    if (s_val_len <= 32) {
        memcpy(&s_32[32 - s_val_len], s_val, s_val_len);
    }
    
    if (compare_be(s_32, SECP256K1_HALF_ORDER, 32) > 0) {
        debug_log("Normalizing high-S signature");
        
        uint8_t new_s[32];
        subtract_be(SECP256K1_ORDER, s_32, new_s, 32);
        
        size_t new_s_start = 0;
        while (new_s_start < 31 && new_s[new_s_start] == 0x00) {
            new_s_start++;
        }
        
        bool need_pad = (new_s[new_s_start] & 0x80) != 0;
        size_t new_s_len = 32 - new_s_start + (need_pad ? 1 : 0);
        
        uint8_t new_sig[72];
        size_t idx = 0;
        
        new_sig[idx++] = 0x30;
        new_sig[idx++] = 0;
        
        new_sig[idx++] = 0x02;
        new_sig[idx++] = r_len;
        memcpy(&new_sig[idx], r_ptr, r_len);
        idx += r_len;
        
        new_sig[idx++] = 0x02;
        new_sig[idx++] = new_s_len;
        if (need_pad) {
            new_sig[idx++] = 0x00;
        }
        memcpy(&new_sig[idx], &new_s[new_s_start], 32 - new_s_start);
        idx += 32 - new_s_start;
        
        new_sig[1] = idx - 2;
        
        memcpy(sig, new_sig, idx);
        *sig_len = idx;
    }
    
    return SE050_OK;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

const char *se050_version(void) {
    return SE050_WALLET_VERSION;
}

const char *se050_error_str(int err) {
    switch (err) {
        case SE050_OK: return "Success";
        case SE050_ERR_NOT_CONNECTED: return "Not connected to SE050";
        case SE050_ERR_CONNECTION_FAILED: return "Connection failed";
        case SE050_ERR_KEY_NOT_FOUND: return "Key not found";
        case SE050_ERR_KEY_EXISTS: return "Key already exists";
        case SE050_ERR_SIGN_FAILED: return "Signing failed";
        case SE050_ERR_INVALID_PARAM: return "Invalid parameter";
        case SE050_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
        case SE050_ERR_SCP03_FAILED: return "SCP03 authentication failed";
        case SE050_ERR_INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

void se050_set_debug(bool enable) {
    g_ctx.debug = enable;
}

bool se050_is_connected(void) {
    return g_ctx.connected;
}

int se050_open_session(const char *port, const char *scp_key_file) {
    sss_status_t status;
    
    if (g_ctx.connected) {
        debug_log("Already connected, closing first");
        se050_close_session();
    }
    
    /* Detect port if not specified */
    if (!port || strlen(port) == 0) {
        port = detect_port();
        if (!port) {
            debug_log("No SE050 port detected");
            return SE050_ERR_CONNECTION_FAILED;
        }
    }
    strncpy(g_ctx.port, port, sizeof(g_ctx.port) - 1);
    debug_log("Using port: %s", g_ctx.port);
    
    /* Set SCP03 key file path via environment variable */
    if (scp_key_file && strlen(scp_key_file) > 0) {
        strncpy(g_ctx.scp_key_file, scp_key_file, sizeof(g_ctx.scp_key_file) - 1);
        setenv("EX_SSS_BOOT_SCP03_PATH", scp_key_file, 1);
        debug_log("SCP03 key file: %s", scp_key_file);
    }
    
    /* Initialize boot context */
    memset(&g_ctx.boot_ctx, 0, sizeof(g_ctx.boot_ctx));
    
    /* Use middleware's boot open - handles SCP03 setup properly */
    status = ex_sss_boot_open(&g_ctx.boot_ctx, g_ctx.port);
    
    if (status != kStatus_SSS_Success) {
        debug_log("ex_sss_boot_open failed: %d", status);
        return SE050_ERR_SCP03_FAILED;
    }
    
    /* Initialize keystore - required for key operations! */
    status = ex_sss_key_store_and_object_init(&g_ctx.boot_ctx);
    if (status != kStatus_SSS_Success) {
        debug_log("ex_sss_key_store_and_object_init failed: %d", status);
        ex_sss_session_close(&g_ctx.boot_ctx);
        return SE050_ERR_INTERNAL;
    }
    
    g_ctx.connected = true;
    debug_log("Session opened successfully");
    
    return SE050_OK;
}

int se050_close_session(void) {
    if (g_ctx.connected) {
        ex_sss_session_close(&g_ctx.boot_ctx);
        memset(&g_ctx.boot_ctx, 0, sizeof(g_ctx.boot_ctx));
        g_ctx.connected = false;
        debug_log("Session closed");
    }
    return SE050_OK;
}

int se050_reconnect(void) {
    char port[256];
    char keyfile[512];
    
    strncpy(port, g_ctx.port, sizeof(port));
    strncpy(keyfile, g_ctx.scp_key_file, sizeof(keyfile));
    
    se050_close_session();
    usleep(500000);
    
    return se050_open_session(port, keyfile);
}

int se050_get_uid(uint8_t *uid, size_t *uid_len) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!uid || !uid_len || *uid_len < UID_MAX_LEN) {
        return SE050_ERR_BUFFER_TOO_SMALL;
    }
    
    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)&g_ctx.boot_ctx.session;
    
    uint8_t uid_buf[32] = {0};
    size_t uid_buf_len = sizeof(uid_buf);
    
    smStatus_t sm_status = Se05x_API_ReadObject(
        &se05x_session->s_ctx,
        kSE05x_AppletResID_UNIQUE_ID,
        0, 0,
        uid_buf, &uid_buf_len
    );
    
    if (sm_status != SM_OK) {
        debug_log("ReadObject for UID failed: 0x%04X", sm_status);
        return SE050_ERR_INTERNAL;
    }
    
    memcpy(uid, uid_buf, uid_buf_len);
    *uid_len = uid_buf_len;
    
    return SE050_OK;
}

int se050_get_random(uint8_t *buf, size_t len) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!buf || len == 0) {
        return SE050_ERR_INVALID_PARAM;
    }
    
    sss_status_t status;
    sss_rng_context_t rng_ctx;
    
    status = sss_rng_context_init(&rng_ctx, &g_ctx.boot_ctx.session);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_rng_get_random(&rng_ctx, buf, len);
    sss_rng_context_free(&rng_ctx);
    
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    return SE050_OK;
}

int se050_get_free_memory(uint32_t *persistent, uint32_t *transient) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)&g_ctx.boot_ctx.session;
    
    uint32_t mem = 0;
    smStatus_t sm_status;
    
    if (persistent) {
        sm_status = Se05x_API_GetFreeMemory(&se05x_session->s_ctx, kSE05x_MemoryType_PERSISTENT, &mem);
        if (sm_status == SM_OK) {
            *persistent = mem;
        } else {
            *persistent = 0;
        }
    }
    
    if (transient) {
        sm_status = Se05x_API_GetFreeMemory(&se05x_session->s_ctx, kSE05x_MemoryType_TRANSIENT_DESELECT, &mem);
        if (sm_status == SM_OK) {
            *transient = mem;
        } else {
            *transient = 0;
        }
    }
    
    return SE050_OK;
}

bool se050_key_exists(uint32_t key_id) {
    if (!g_ctx.connected) {
        return false;
    }
    
    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)&g_ctx.boot_ctx.session;
    
    SE05x_Result_t result;
    smStatus_t sm_status = Se05x_API_CheckObjectExists(&se05x_session->s_ctx, key_id, &result);
    
    return (sm_status == SM_OK && result == kSE05x_Result_SUCCESS);
}

int se050_generate_keypair(uint32_t key_id) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (se050_key_exists(key_id)) {
        debug_log("Key 0x%08X already exists", key_id);
        return SE050_ERR_KEY_EXISTS;
    }
    
    sss_status_t status;
    sss_object_t key_obj;
    
    status = sss_key_object_init(&key_obj, &g_ctx.boot_ctx.ks);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_key_object_allocate_handle(&key_obj, key_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_K,
        256, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_key_store_generate_key(&g_ctx.boot_ctx.ks, &key_obj, 256, NULL);
    if (status != kStatus_SSS_Success) {
        debug_log("Key generation failed: %d", status);
        return SE050_ERR_INTERNAL;
    }
    
    debug_log("Generated keypair at 0x%08X", key_id);
    return SE050_OK;
}

int se050_import_keypair(uint32_t key_id, const uint8_t *private_key) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!private_key) {
        return SE050_ERR_INVALID_PARAM;
    }
    
    if (se050_key_exists(key_id)) {
        debug_log("Deleting existing key at 0x%08X", key_id);
        se050_delete_key(key_id);
    }
    
    sss_status_t status;
    sss_object_t key_obj;
    
    /*
     * SE050 expects SEC1 DER format (RFC 5915) for EC key import:
     *
     * ECPrivateKey ::= SEQUENCE {
     *   version        INTEGER (1)
     *   privateKey     OCTET STRING (32 bytes for secp256k1)
     *   parameters [0] OID secp256k1
     *   publicKey  [1] BIT STRING (uncompressed 65-byte pubkey)
     * }
     *
     * Total structure for secp256k1 with pubkey: 118 bytes (0x76)
     * 30 76 02 01 01 04 20 <32> A0 07 06 05 2B 81 04 00 0A A1 44 03 42 00 <65>
     */
    
    /* Derive public key from private key using mbedtls */
    uint8_t pubkey[65] = {0};
    
    {
        mbedtls_ecp_group grp;
        mbedtls_ecp_point Q;
        mbedtls_mpi d;
        
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&Q);
        mbedtls_mpi_init(&d);
        
        /* Load secp256k1 curve */
        int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
        if (ret != 0) {
            debug_log("Failed to load secp256k1 curve: %d", ret);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&Q);
            mbedtls_mpi_free(&d);
            return SE050_ERR_INTERNAL;
        }
        
        /* Import private key as big number */
        ret = mbedtls_mpi_read_binary(&d, private_key, 32);
        if (ret != 0) {
            debug_log("Failed to read private key: %d", ret);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&Q);
            mbedtls_mpi_free(&d);
            return SE050_ERR_INTERNAL;
        }
        
        /* Q = d * G (derive public key) */
        ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, NULL, NULL);
        if (ret != 0) {
            debug_log("Failed to derive public key: %d", ret);
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&Q);
            mbedtls_mpi_free(&d);
            return SE050_ERR_INTERNAL;
        }
        
        /* Export public key as uncompressed point (04 || x || y) */
        size_t olen = 0;
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
            &olen, pubkey, sizeof(pubkey));
        
        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&Q);
        mbedtls_mpi_free(&d);
        
        if (ret != 0 || olen != 65) {
            debug_log("Failed to export public key: %d, len=%zu", ret, olen);
            return SE050_ERR_INTERNAL;
        }
        
        debug_log("Derived pubkey: %02X%02X...%02X%02X", 
            pubkey[0], pubkey[1], pubkey[63], pubkey[64]);
    }
    
    /*
     * Build SEC1 DER: 
     * 30 76                    -- SEQUENCE, 118 bytes
     *   02 01 01               -- INTEGER 1 (version)
     *   04 20 <privkey>        -- OCTET STRING, 32 bytes
     *   A0 07                  -- [0] EXPLICIT, 7 bytes
     *     06 05 2B 81 04 00 0A -- OID secp256k1
     *   A1 44                  -- [1] EXPLICIT, 68 bytes
     *     03 42 00 <pubkey>    -- BIT STRING, 65 bytes + 1 unused bits byte
     */
    uint8_t der_key[120];
    size_t idx = 0;
    
    der_key[idx++] = 0x30;  /* SEQUENCE */
    der_key[idx++] = 0x74;  /* 116 bytes */
    
    /* version INTEGER 1 */
    der_key[idx++] = 0x02;
    der_key[idx++] = 0x01;
    der_key[idx++] = 0x01;
    
    /* privateKey OCTET STRING */
    der_key[idx++] = 0x04;
    der_key[idx++] = 0x20;  /* 32 bytes */
    memcpy(&der_key[idx], private_key, 32);
    idx += 32;
    
    /* parameters [0] OID secp256k1 */
    der_key[idx++] = 0xA0;
    der_key[idx++] = 0x07;
    der_key[idx++] = 0x06;
    der_key[idx++] = 0x05;
    der_key[idx++] = 0x2B;
    der_key[idx++] = 0x81;
    der_key[idx++] = 0x04;
    der_key[idx++] = 0x00;
    der_key[idx++] = 0x0A;
    
    /* publicKey [1] BIT STRING */
    der_key[idx++] = 0xA1;
    der_key[idx++] = 0x44;  /* 68 bytes */
    der_key[idx++] = 0x03;  /* BIT STRING */
    der_key[idx++] = 0x42;  /* 66 bytes */
    der_key[idx++] = 0x00;  /* no unused bits */
    memcpy(&der_key[idx], pubkey, 65);
    idx += 65;
    
    debug_log("Built SEC1 DER key: %zu bytes", idx);
    
    /* Import to SE050 */
    status = sss_key_object_init(&key_obj, &g_ctx.boot_ctx.ks);
    if (status != kStatus_SSS_Success) {
        debug_log("key_object_init failed");
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_key_object_allocate_handle(&key_obj, key_id,
        kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_K,
        256, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        debug_log("key_object_allocate_handle failed");
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_key_store_set_key(&g_ctx.boot_ctx.ks, &key_obj,
        der_key, idx, 256, NULL, 0);
    
    if (status != kStatus_SSS_Success) {
        debug_log("Key import failed: %d", status);
        return SE050_ERR_INTERNAL;
    }
    
    debug_log("Imported keypair at 0x%08X", key_id);
    return SE050_OK;
}

int se050_get_pubkey(uint32_t key_id, uint8_t *pubkey, size_t *len) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!pubkey || !len || *len < SECP256K1_PUBKEY_LEN) {
        return SE050_ERR_BUFFER_TOO_SMALL;
    }
    
    if (!se050_key_exists(key_id)) {
        return SE050_ERR_KEY_NOT_FOUND;
    }
    
    sss_status_t status;
    sss_object_t key_obj;
    
    status = sss_key_object_init(&key_obj, &g_ctx.boot_ctx.ks);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    /* For keypairs, we need to allocate handle as Public part to read pubkey */
    status = sss_key_object_allocate_handle(&key_obj, key_id,
        kSSS_KeyPart_Public, kSSS_CipherType_EC_NIST_K,
        256, kKeyObject_Mode_Persistent);
    if (status != kStatus_SSS_Success) {
        debug_log("Allocate handle for pubkey read failed: %d", status);
        return SE050_ERR_INTERNAL;
    }
    
    size_t pubkey_bits = 256;
    status = sss_key_store_get_key(&g_ctx.boot_ctx.ks, &key_obj,
        pubkey, len, &pubkey_bits);
    
    if (status != kStatus_SSS_Success) {
        debug_log("Get pubkey failed: %d", status);
        return SE050_ERR_INTERNAL;
    }
    
    debug_log("Got pubkey: %zu bytes", *len);
    return SE050_OK;
}

int se050_delete_key(uint32_t key_id) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!se050_key_exists(key_id)) {
        return SE050_ERR_KEY_NOT_FOUND;
    }
    
    sss_se05x_session_t *se05x_session = (sss_se05x_session_t *)&g_ctx.boot_ctx.session;
    
    smStatus_t sm_status = Se05x_API_DeleteSecureObject(&se05x_session->s_ctx, key_id);
    
    if (sm_status != SM_OK) {
        debug_log("Delete key failed: 0x%04X", sm_status);
        return SE050_ERR_INTERNAL;
    }
    
    debug_log("Deleted key 0x%08X", key_id);
    return SE050_OK;
}

int se050_sign_hash(uint32_t key_id, const uint8_t *hash,
                    uint8_t *signature, size_t *sig_len) {
    if (!g_ctx.connected) {
        return SE050_ERR_NOT_CONNECTED;
    }
    
    if (!hash || !signature || !sig_len || *sig_len < MAX_SIGNATURE_LEN) {
        return SE050_ERR_INVALID_PARAM;
    }
    
    if (!se050_key_exists(key_id)) {
        return SE050_ERR_KEY_NOT_FOUND;
    }
    
    sss_status_t status;
    sss_object_t key_obj;
    sss_asymmetric_t asym_ctx;
    
    status = sss_key_object_init(&key_obj, &g_ctx.boot_ctx.ks);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_key_object_get_handle(&key_obj, key_id);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_KEY_NOT_FOUND;
    }
    
    status = sss_asymmetric_context_init(&asym_ctx, &g_ctx.boot_ctx.session,
        &key_obj, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        return SE050_ERR_INTERNAL;
    }
    
    status = sss_asymmetric_sign_digest(&asym_ctx, (uint8_t *)hash, SHA256_HASH_LEN,
        signature, sig_len);
    
    sss_asymmetric_context_free(&asym_ctx);
    
    if (status != kStatus_SSS_Success) {
        debug_log("Signing failed: %d", status);
        return SE050_ERR_SIGN_FAILED;
    }
    
    int ret = normalize_signature(signature, sig_len);
    if (ret != SE050_OK) {
        return ret;
    }
    
    debug_log("Signed hash with key 0x%08X, sig len=%zu", key_id, *sig_len);
    return SE050_OK;
}

int se050_sign_data(uint32_t key_id, const uint8_t *data, size_t data_len,
                    uint8_t *signature, size_t *sig_len) {
    (void)key_id;
    (void)data;
    (void)data_len;
    (void)signature;
    (void)sig_len;
    
    debug_log("se050_sign_data: Use se050_sign_hash with pre-hashed data");
    return SE050_ERR_INTERNAL;
}
