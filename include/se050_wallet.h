/*
 * SE050 Hardware Wallet C Library
 * 
 * Direct SSS API interface replacing ssscli subprocess calls.
 * Provides SCP03 encrypted communication with SE050.
 *
 * Copyright 2025 _SiCk @ afflicted.sh
 * SPDX-License-Identifier: MIT
 */

#ifndef SE050_WALLET_H
#define SE050_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

typedef enum {
    SE050_OK = 0,
    SE050_ERR_NOT_CONNECTED = -1,
    SE050_ERR_CONNECTION_FAILED = -2,
    SE050_ERR_KEY_NOT_FOUND = -3,
    SE050_ERR_KEY_EXISTS = -4,
    SE050_ERR_SIGN_FAILED = -5,
    SE050_ERR_INVALID_PARAM = -6,
    SE050_ERR_BUFFER_TOO_SMALL = -7,
    SE050_ERR_SCP03_FAILED = -8,
    SE050_ERR_INTERNAL = -9,
} se050_error_t;

/* ============================================================================
 * Session Management
 * ============================================================================ */

/**
 * Open SCP03 encrypted session to SE050
 * 
 * @param port          Serial port (e.g., "/dev/ttyACM0") or NULL for auto-detect
 * @param scp_key_file  Path to SCP03 key file with ENC/MAC/DEK keys
 * @return SE050_OK on success, negative error code on failure
 */
int se050_open_session(const char *port, const char *scp_key_file);

/**
 * Close SE050 session
 * @return SE050_OK on success
 */
int se050_close_session(void);

/**
 * Check if session is currently open
 * @return true if connected, false otherwise
 */
bool se050_is_connected(void);

/**
 * Reconnect (close and reopen session)
 * @return SE050_OK on success
 */
int se050_reconnect(void);

/* ============================================================================
 * Device Info
 * ============================================================================ */

/**
 * Get SE050 unique identifier
 * 
 * @param uid       Output buffer for UID (at least 18 bytes)
 * @param uid_len   In: buffer size, Out: actual UID length
 * @return SE050_OK on success
 */
int se050_get_uid(uint8_t *uid, size_t *uid_len);

/**
 * Get random bytes from SE050 TRNG
 * 
 * @param buf       Output buffer
 * @param len       Number of random bytes to get
 * @return SE050_OK on success
 */
int se050_get_random(uint8_t *buf, size_t len);

/**
 * Get available free memory on SE050
 * 
 * @param persistent    Output: persistent memory bytes available
 * @param transient     Output: transient memory bytes available
 * @return SE050_OK on success
 */
int se050_get_free_memory(uint32_t *persistent, uint32_t *transient);

/* ============================================================================
 * Key Management
 * ============================================================================ */

/**
 * Check if key exists at given slot
 * 
 * @param key_id    Key slot ID (e.g., 0x20000001)
 * @return true if key exists, false otherwise
 */
bool se050_key_exists(uint32_t key_id);

/**
 * Generate secp256k1 keypair on SE050
 * 
 * @param key_id    Key slot ID to store keypair
 * @return SE050_OK on success, SE050_ERR_KEY_EXISTS if slot occupied
 */
int se050_generate_keypair(uint32_t key_id);

/**
 * Import secp256k1 private key to SE050
 * 
 * @param key_id        Key slot ID
 * @param private_key   32-byte private key
 * @return SE050_OK on success
 */
int se050_import_keypair(uint32_t key_id, const uint8_t *private_key);

/**
 * Export public key from SE050
 * 
 * @param key_id    Key slot ID
 * @param pubkey    Output buffer for uncompressed pubkey (65 bytes: 04 || X || Y)
 * @param len       In: buffer size, Out: actual pubkey length
 * @return SE050_OK on success
 */
int se050_get_pubkey(uint32_t key_id, uint8_t *pubkey, size_t *len);

/**
 * Delete key from SE050
 * 
 * @param key_id    Key slot ID to delete
 * @return SE050_OK on success, SE050_ERR_KEY_NOT_FOUND if not exists
 */
int se050_delete_key(uint32_t key_id);

/* ============================================================================
 * Cryptographic Operations
 * ============================================================================ */

/**
 * Sign SHA256 hash with secp256k1 key
 * 
 * The signature is returned in DER format with low-S normalization
 * per BIP-62.
 * 
 * @param key_id        Key slot ID
 * @param hash          32-byte SHA256 hash to sign
 * @param signature     Output buffer for DER signature (max 72 bytes)
 * @param sig_len       In: buffer size, Out: actual signature length
 * @return SE050_OK on success
 */
int se050_sign_hash(uint32_t key_id, const uint8_t *hash, 
                    uint8_t *signature, size_t *sig_len);

/**
 * Sign data with SHA256 hashing done by SE050
 * 
 * SE050 will hash the data before signing.
 * 
 * @param key_id        Key slot ID
 * @param data          Data to hash and sign
 * @param data_len      Length of data
 * @param signature     Output buffer for DER signature
 * @param sig_len       In: buffer size, Out: actual signature length
 * @return SE050_OK on success
 */
int se050_sign_data(uint32_t key_id, const uint8_t *data, size_t data_len,
                    uint8_t *signature, size_t *sig_len);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Get error message for error code
 * @param err   Error code
 * @return Human-readable error string
 */
const char *se050_error_str(int err);

/**
 * Set debug/verbose output
 * @param enable    true to enable debug output
 */
void se050_set_debug(bool enable);

/**
 * Get library version string
 * @return Version string (e.g., "1.0.0")
 */
const char *se050_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SE050_WALLET_H */
