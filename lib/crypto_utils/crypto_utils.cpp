#include "crypto_utils.h"

bool crypto_debug_enable = false;

bool Crypto_initRandomGenerator(mbedtls_ctr_drbg_context *ctx, int8_t *personalization_info, uint16_t personalization_info_len)
{
    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_init(ctx);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(ctx, mbedtls_entropy_func, &entropy, (const unsigned char *) personalization_info, personalization_info_len) != 0)
      return false;
    
    return true;
}

bool Crypto_Random(mbedtls_ctr_drbg_context *ctx, uint8_t *output, uint16_t output_size)
{
  if (mbedtls_ctr_drbg_random(ctx, output, output_size) != 0)
    return false;

  if (crypto_debug_enable)
    Crypto_debugPrint((int8_t *)"random number", output, output_size);
  
  return true;
}

bool Crypto_Digest(mbedtls_md_context_t *ctx, DIGEST_TYPE d_type, uint8_t *input, uint16_t input_size, uint8_t *output, uint8_t *key, uint16_t key_len)
{
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(ctx);

    if (mbedtls_md_setup(ctx, mbedtls_md_info_from_type(md_type), d_type) != 0)
      return false;
    
    if (d_type == SHA256)
    {
      if (mbedtls_md_starts(ctx) != 0)
        return false;

      if (mbedtls_md_update(ctx, (const unsigned char *) input, input_size) != 0)
        return false;

      if (mbedtls_md_finish(ctx, output) != 0)
        return false;
    }
    else if (d_type == HMAC_SHA256)
    {
      if (mbedtls_md_hmac_starts(ctx, (const unsigned char *) key, key_len))
        return false;

      if (mbedtls_md_hmac_update(ctx, (const unsigned char *) input, input_size) != 0)
        return false;

      if (mbedtls_md_hmac_finish(ctx, output) != 0)
        return false;
    }
    else
    {
      return false;
    }

    mbedtls_md_free(ctx);

    if (crypto_debug_enable)
      Crypto_debugPrint((int8_t *)"digest", output, 32);

    return true;
}

bool Crypto_keyGen(mbedtls_ecdh_context *ecdh_ctx, mbedtls_ctr_drbg_context *drbg_ctx, mbedtls_ecp_group_id curve_type)
{
    mbedtls_ecdh_init(ecdh_ctx);

    if (mbedtls_ecp_group_load(&((*ecdh_ctx).grp), curve_type) != 0)
      return false;

    if (mbedtls_ecdh_gen_public(&((*ecdh_ctx).grp), &((*ecdh_ctx).d), &((*ecdh_ctx).Q), mbedtls_ctr_drbg_random, drbg_ctx) != 0)
      return false;

    return true;
}

bool Crypto_ECDH(mbedtls_ecdh_context *ctx)
{
  if (mbedtls_ecdh_compute_shared( &(*ctx).grp, &(*ctx).z, &(*ctx).Qp, &(*ctx).d, 0, 0) != 0)
    return false;

  return true;
}


bool Crypto_AES(mbedtls_aes_context *ctx, ENCRYPTION_DIRECTION_TYPE ed_type, uint8_t *key, uint16_t key_len, uint8_t iv[16], uint8_t *input, uint8_t *output, uint16_t length)
{
    mbedtls_aes_init(ctx);
    uint16_t padding = 16 - length % 16;

    // prepraviti padding
    uint8_t tmp[128];
    memset(tmp, 0x00, 128);
    memcpy(tmp, input, length);

    if (ed_type == ENCRYPT)
    {
      if (mbedtls_aes_setkey_enc(ctx, (const unsigned char*) key, key_len) != 0)
        return false;
      
      if (mbedtls_aes_crypt_cbc(ctx, (int)MBEDTLS_AES_ENCRYPT, length + padding, iv, tmp, output) != 0)
        return false;
    }
    else if (ed_type == DECRYPT)
    {
      if (mbedtls_aes_setkey_dec(ctx, (const unsigned char*) key, key_len) != 0)
        return false;
      
      if (mbedtls_aes_crypt_cbc(ctx, (int)MBEDTLS_AES_DECRYPT, length + padding, iv, tmp, output) != 0)
        return false;
    }
    else
    {
      return false;
    }
    mbedtls_aes_free(ctx);

    if (crypto_debug_enable)
      Crypto_debugPrint((int8_t *)"aes output", output, length);

    return true;
}


bool Crypto_getPublicKey(mbedtls_ecdh_context *ctx, uint8_t *public_key)
{
    if (mbedtls_mpi_write_binary(&(*ctx).Q.X, public_key, 32) != 0)
      return false;

    if (mbedtls_mpi_write_binary(&(*ctx).Q.Y, public_key + 32, 32) != 0)
      return false;

    if (crypto_debug_enable)
      Crypto_debugPrint((int8_t *)"public key", public_key, 64);

    return true;
}

bool Crypto_getPrivateKey(mbedtls_ecdh_context *ctx, uint8_t *private_key)
{
    if (mbedtls_mpi_write_binary(&(*ctx).d, private_key, 32) != 0)
      return false;
  
    if (crypto_debug_enable)
      Crypto_debugPrint((int8_t *)"private key", private_key, 32);

    return true;
}

bool Crypto_getSharedSecret(mbedtls_ecdh_context *ctx, uint8_t *shared_secret)
{
  if (mbedtls_mpi_write_binary(&(*ctx).z, shared_secret, 32) != 0)
    return false;
  
  if (crypto_debug_enable)
      Crypto_debugPrint((int8_t *)"shared secret", shared_secret, 32);

  return true;
}


bool Crypto_setPeerPublicKey(mbedtls_ecdh_context *ctx, uint8_t *peer_public_key)
{
    if (mbedtls_mpi_lset(&(*ctx).Qp.Z, 1) != 0)
      return false;

    if (mbedtls_mpi_read_binary(&(*ctx).Qp.X, peer_public_key, 32) != 0)
      return false;

    if (mbedtls_mpi_read_binary(&(*ctx).Qp.Y, peer_public_key + 32, 32) != 0)
      return false;

    return true;
}


bool Crypto_compareBytes(uint8_t *input1, uint8_t *input2, uint16_t len)
{
    for(uint16_t iter = 0; iter < len; iter++)
      if(input1[iter] != input2[iter])
        return false;
    return true;
}

void Crypto_debugEnable(bool enable)
{
  crypto_debug_enable = enable;
}

void Crypto_debugPrint(int8_t *title, uint8_t *data, uint16_t data_len)
{
    DEBUG_STREAM.print(String((char *)title) + ":");
    for(uint16_t i = 0; i < data_len; i++)
    {
      char str[3];
      sprintf(str, "%02x", (int)data[i]);
      DEBUG_STREAM.print(str);
    }
    DEBUG_STREAM.println();
}