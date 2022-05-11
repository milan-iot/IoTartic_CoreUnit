#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H

/// used libraries
#include <Arduino.h>
#include "mbedtls/md.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

/// debug macro
#define DEBUG_STREAM  Serial

/// type of digest to be generated
typedef enum {SHA256, HMAC_SHA256} DIGEST_TYPE;
/// type of encryption direction
typedef enum {ENCRYPT, DECRYPT} ENCRYPTION_DIRECTION_TYPE;

/**
* Function used for random number generator initialization.
* @param ctx - pointer to random number generator context that is used
* @param personalization_info - pointer to bytes used as personalization information, which is salt value for random number generator (can be NULL)
* @param personalization_info_len - size of personalization info in bytes
* @return - true if operation is successful, otherwise false
*/
bool Crypto_initRandomGenerator(mbedtls_ctr_drbg_context *ctx, int8_t *personalization_info, uint16_t personalization_info_len);
/**
* Function used to generate random bytes.
* @param ctx - pointer to random number generator context that is used
* @param output - pointer to buffer where random bytes will be stored
* @param output_size - length of random bytes we want to generate
* @return - true if operation is successful, otherwise false
*/
bool Crypto_Random(mbedtls_ctr_drbg_context *ctx, uint8_t *output, uint16_t output_size);
/**
* Function used to generate digest (SHA256 or HMAC_SHA256) from given bytes.
* @param ctx - pointer to message digest context that is used
* @param d_type - type of digest that will be created
* @param input - pointer to buffer where input bytes of data are stored
* @param input_size - length of input data bytes
* @param output - pointer to buffer where output bytes (digest) of data will be stored 
* @param key - pointer to buffer where key (in case of HMAC_SHA256 digest) is stored 
* @param key_len - length of key in bytes (in case of HMAC_SHA256 digest)
* @return - true if operation is successful, otherwise false
*/
bool Crypto_Digest(mbedtls_md_context_t *ctx, DIGEST_TYPE d_type, uint8_t *input, uint16_t input_size, uint8_t *output, uint8_t *key = NULL, uint16_t key_len = 0);
/**
* Function that performs AES encryption.
* @param ctx - pointer to aes context that is used
* @param ed_type - type of encryption direction to be used (encrypt/decrypt)
* @param key - pointer to buffer where key to be used is stored
* @param key_len - length of key
* @param iv - pointer to buffer where initialization vector to be used is stored
* @param input - pointer to buffer where input data bytes to be encrypted/decrypted are stored
* @param output - pointer to buffer where output data bytes will be stored
* @param length - length of data (in bytes) to be encrypted/decrypted
* @return - true if operation is successful, otherwise false
*/
bool Crypto_AES(mbedtls_aes_context *ctx, ENCRYPTION_DIRECTION_TYPE ed_type, uint8_t *key, uint16_t key_len, uint8_t iv[16], uint8_t *input, uint8_t *output, uint16_t length);
/**
* Function that performs Elliptic Curve key generation of public/private key pair.
* @param ecdh_ctx - pointer to ecdh context that is used
* @param drbg_ctx - pointer to random number generator context that is used
* @param curve_type - type of curve to be used
* @return - true if operation is successful, otherwise false
*/
bool Crypto_keyGen(mbedtls_ecdh_context *ecdh_ctx, mbedtls_ctr_drbg_context *drbg_ctx, mbedtls_ecp_group_id curve_type);
/**
* Function that performs Elliptic Curve Diffie-Hellman (ECDH) function.
* @param ctx - pointer to ecdh context that is used
* @return - true if operation is successful, otherwise false
*/
bool Crypto_ECDH(mbedtls_ecdh_context *ctx);

/**
* Getter function used for retrieving generated public key.
* @param ctx - pointer to ecdh context that is used
* @param public_key - pointer to buffer of data that represent public key will be stored (64 bytes)
* @return - true if operation is successful, otherwise false
*/
bool Crypto_getPublicKey(mbedtls_ecdh_context *ctx, uint8_t *public_key);
/**
* Getter function used for retrieving generated private key.
* @param ctx - pointer to ecdh context that is used
* @param private_key - pointer to buffer of data that represent private key will be stored (32 bytes)
* @return - true if operation is successful, otherwise false
*/
bool Crypto_getPrivateKey(mbedtls_ecdh_context *ctx, uint8_t *private_key);
/**
* Getter function used for retrieving generated shared key.
* @param ctx - pointer to ecdh context that is used
* @param shared_secret - pointer to buffer of data that represent shared key will be stored (32 bytes)
* @return - true if operation is successful, otherwise false
*/
bool Crypto_getSharedSecret(mbedtls_ecdh_context *ctx, uint8_t *shared_secret);
/**
* Setter function used for setting public key from another peer that will be used in Elliptic Curve Diffie-Hellman (ECDH) function.
* @param ctx - pointer to ecdh context that is used
* @param peer_public_key - pointer to buffer of data that represent peer public key (64 bytes)
* @return - true if operation is successful, otherwise false
*/
bool Crypto_setPeerPublicKey(mbedtls_ecdh_context *ctx, uint8_t *peer_public_key);


/**
* Utility function used for comparison of two arrays of bytes.
* @param input1 - pointer to first buffer that stores bytes to be compared
* @param input2 - pointer to second buffer that stores bytes to be compared
* @param len - length of data to be compared
* @return - true if arrays are same, otherwise false
*/
bool Crypto_compareBytes(uint8_t *input1, uint8_t *input2, uint16_t len);

/**
* Utility function used to enable/disable debug prints via UART.
* @param enable - parameter used for enabling debug prints (true-enable, false-disable)
* @return - no return value
*/
void Crypto_debugEnable(bool enable);

/**
* Utility function that prints bytes for debug purposes via UART.
* @param title - string used to entitle data
* @param data - pointer to buffer where bytes of data to be printed are stored
* @param data_len - length of data to be printed
* @return - true if operation is successful, otherwise false
*/
void Crypto_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len);

#endif //_CRYPTO_UTILS_H
