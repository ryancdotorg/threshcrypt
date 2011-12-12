/* threshcrypt crypt.c
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <tomcrypt.h>

#include "common.h"
#include "util.h"
#include "crypt.h"

int crypt_data(const unsigned char *data_in,
                     unsigned char *data_out,  size_t data_size,
               const unsigned char *data_mkey, size_t data_mkey_size,
                     unsigned char *data_new_hmac,
               const unsigned char *data_chk_hmac,
                     size_t data_hmac_size,
                     int mode) {
  if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
    fprintf(stderr, "crypt_data called with invalid mode %d\n", mode);
    return -1;
  }

  symmetric_CTR ctr;
  int err;
  int ret = 0; /* return code */
  unsigned char IV[16];
  size_t IV_size = sizeof(IV);
  memset(IV, 0, sizeof(IV));
  int hash_idx = find_hash("sha256");
  size_t data_ckey_size, data_hkey_size;
  data_ckey_size = data_hkey_size = data_mkey_size;
  unsigned char *data_ckey = safe_malloc(data_mkey_size);
  unsigned char *data_hkey = safe_malloc(data_mkey_size);

  pbkdf2(data_mkey, data_mkey_size, "H", 1, SUBKEY_ITER, hash_idx, data_hkey, &data_hkey_size);
  pbkdf2(data_mkey, data_mkey_size, "C", 1, SUBKEY_ITER, hash_idx, data_ckey, &data_ckey_size);
  pbkdf2(data_mkey, data_mkey_size, "I", 1, SUBKEY_ITER, hash_idx, IV, &IV_size); /* not strictly needed */

  if (mode == MODE_DECRYPT && data_chk_hmac != NULL) {
    if ((err = hmac_vrfymem(hash_idx,
                            data_hkey, data_hkey_size,
                            data_in, data_size,
                            data_chk_hmac, &data_hmac_size)) != CRYPT_OK) {
      fprintf(stderr, "hmac error: %s\n", error_to_string(err));
      ret = -1; goto crypt_data_cleanup;
    }
  }

  if ((err = ctr_start(find_cipher("aes"), IV, data_ckey, data_ckey_size, 0,
                       CTR_COUNTER_LITTLE_ENDIAN | 4, &ctr)) != CRYPT_OK) {
    fprintf(stderr, "Error initializing cipher: %d\n", err);
    ret = -1; goto crypt_data_cleanup;
  }

  switch (mode) {
    case MODE_DECRYPT: 
      if ((err = ctr_decrypt(data_in, data_out, data_size, &ctr)) != CRYPT_OK) {
        fprintf(stderr, "ctr_decrypt error: %s\n", error_to_string(err));
        ret = -1;
        goto crypt_data_cleanup;
      }
      break;
    case MODE_ENCRYPT: 
      if ((err = ctr_encrypt(data_in, data_out, data_size, &ctr)) != CRYPT_OK) {
        fprintf(stderr, "ctr_encrypt error: %s\n", error_to_string(err));
        ret = -1; goto crypt_data_cleanup;
      }
      if (data_new_hmac != NULL) {
        if ((err = hmac_memory(hash_idx,
                               data_hkey, data_hkey_size,
                               data_out, data_size,
                               data_new_hmac, &data_hmac_size)) != CRYPT_OK) {
          fprintf(stderr, "hmac error: %s\n", error_to_string(err)); 
          ret = -1; goto crypt_data_cleanup;
        }
      }
      break;
  }


  // before returning, make sure key material isn't in memory
  crypt_data_cleanup:
  wipe_free(data_hkey, data_hkey_size);
  wipe_free(data_ckey, data_ckey_size); 
  memset(IV, 0, IV_size); 
  return ret;
}

/* Like hmac_memory, but verifies */
int hmac_vrfymem(int hash,
                 const unsigned char *key,  unsigned long  keylen,
                 const unsigned char *in,   unsigned long  inlen,
                 const unsigned char *vrfy, unsigned long *outlen) {
  unsigned char *out = safe_malloc(*outlen);
  int err;
  if ((err = hmac_memory(hash, key, keylen, in, inlen, out, outlen)) != CRYPT_OK) {
    safe_free(out);
    return err;
  }
  if (memcmp(vrfy, out, *outlen) != 0) {
    safe_free(out);
    return CRYPT_ERROR;
  }
  safe_free(out);
  return CRYPT_OK;
}

int pbkdf2_vrfy(const unsigned char *pass, unsigned long  pass_len,
                const unsigned char *salt, unsigned long  salt_len,
                               int   iter,          int   hash_idx, 
                const unsigned char *vrfy, unsigned long *vrfylen) {
  unsigned char *out = safe_malloc(*vrfylen);
  int err;
  if ((err = pbkdf2(pass, pass_len, salt, salt_len,
                    iter, hash_idx, out,  vrfylen)) != CRYPT_OK) {
    safe_free(out);
    return err;
  }
  if (memcmp(vrfy, out, *vrfylen) != 0) {
    safe_free(out);
    return CRYPT_ERROR;
  }
  safe_free(out);
  return CRYPT_OK;
}

// vim: ts=2 sw=2 et ai si
