/* threshcrypt shares.c
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 * Portions of this file are derived from libgfshare examples which are
 * Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006-2011
*/

#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libgfshare.h>
#include <tomcrypt.h>

#include "common.h"
#include "util.h"
#include "shares.h"
#include "crypt.h"

int tc_gfsplit(header_data_t *header) {
  int err;
  unsigned int i, j;  
  share_data_t *share;
  gfshare_ctx *G;

  assert(header->nshares > 1);
  assert(header->thresh > 1);
  assert(header->thresh <= header->nshares);

  unsigned char *sharenrs = safe_malloc(header->nshares);

  /* master key setup */
  gfshare_fill_rand(header->master_key,  header->key_size);
  gfshare_fill_rand(header->master_salt, SALT_SIZE);
  /* Add (hopefully) some extra protection against potentially weak PRNG
   * TODO use a hash for this... */
  for (i = 0; i < header->nshares; i++ ) {
    share = &(header->shares[i]);
    memxor(header->master_key, share->key, header->key_size);
  }

  size_t hmac_size = header->hmac_size;
  if ((err = pbkdf2(header->master_key, header->key_size,
                    header->master_salt, SALT_SIZE, SUBKEY_ITER,
                    find_hash("sha256"), header->master_hmac, &hmac_size)) != CRYPT_OK) {
    fprintf(stderr, "PBKDF2 failed: %d\n", err);
  }

  fprintf(stderr, "MasterSlt: ");
  for (i = 0;i < SALT_SIZE;i++) {
    fprintf(stderr, "%02x", header->master_salt[i]);
  }
  fprintf(stderr, "\n");
 
  fprintf(stderr, "MasterKey: ");
  for (i = 0;i < header->key_size;i++) {
    fprintf(stderr, "%02x", header->master_key[i]);
  }
  fprintf(stderr, "\n");
  
  fprintf(stderr, "MasterMAC: ");
  for (i = 0;i < header->hmac_size;i++) {
    fprintf(stderr, "%02x", header->master_hmac[i]);
  }
  fprintf(stderr, "\n\n");
  /* end master key setup */


  /* This is carry-over from the gfsplit example program.
     I don't know why sequential share numbers are not used. */
  for (i = 0; i < header->nshares; i++ ) {
    /* TODO switch to a proper shuffle algorighm */
    unsigned char proposed = (random() & 0xff00) >> 8;
    if( proposed == 0 ) {
      proposed = 1;
    }
    SHARENR_TRY_AGAIN:
    for( j = 0; j < i; ++j ) {
      if( sharenrs[j] == proposed ) {
        proposed++;
        if( proposed == 0 ) proposed = 1;
        goto SHARENR_TRY_AGAIN;
      }
    }
    sharenrs[i] = proposed;
  }

  G = gfshare_ctx_init_enc( sharenrs, header->nshares, header->thresh, header->key_size);
  if ( !G ) {
    perror("gfshare_ctx_init_enc");
    return -1;
  }

  gfshare_ctx_enc_setsecret(G, header->master_key);

  for (i = 0; i < header->nshares; i++ ) {
    share = &(header->shares[i]);
    share->ptxt = safe_malloc(header->share_size);
    share->ctxt = safe_malloc(header->share_size);
    share->hmac = safe_malloc(header->hmac_size);

    share->ptxt[0] = sharenrs[i];
    gfshare_ctx_enc_getshare(G, i, share->ptxt + 1);
    
    fprintf(stderr, "Salt [%02x]: ", i);
    for (j = 0;j < SALT_SIZE;j++) {
      fprintf(stderr, "%02x", share->salt[j]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "Key  [%02x]: ", i);
    for (j = 0;j < header->key_size;j++) {
      fprintf(stderr, "%02x", share->key[j]);
    }
    fprintf(stderr, "\n"); 
    
    fprintf(stderr, "Share[%02x]: ", i);
    for (j = 0;j < header->share_size;j++) {
      fprintf(stderr, "%02x", share->ptxt[j]);
    }
    fprintf(stderr, "\n");

    if ((err = encrypt_data(share->ptxt, share->ctxt, header->share_size,
                            share->key,  header->key_size,
                            share->hmac, header->hmac_size)) != 0) {
      fprintf(stderr, "Encrypt failed: %d\n", err);
    }
    memset(share->ptxt, 0, header->share_size);
#ifdef NOTESTDECRYPT
    memset(share->key,  0, header->key_size);
#endif

    fprintf(stderr, "Crypt[%02x]: ", i);
    for (j = 0;j < header->share_size;j++) {
      fprintf(stderr, "%02x", share->ctxt[j]);
    }
    fprintf(stderr, "\n");

#ifndef NOTESTDECRYPT
    if ((err = decrypt_data(share->ctxt, share->ptxt, header->share_size,
                            share->key,  header->key_size,
                            share->hmac, header->hmac_size)) != 0) {
      fprintf(stderr, "Decrypt failed: %d\n", err);
    }
    memset(share->key,  0, header->key_size);

    fprintf(stderr, "Plain[%02x]: ", i);
    for (j = 0;j < header->share_size;j++) {
      fprintf(stderr, "%02x", share->ptxt[j]);
    }
    fprintf(stderr, "\n");
    memset(share->ptxt, 0, header->share_size);
    memset(share->key,  0, header->key_size);
#endif
    wipe_free(share->ptxt, header->share_size);
    wipe_free(share->key,  header->key_size);
    fprintf(stderr, "MAC  [%02x]: ", i);
    for (j = 0;j < header->hmac_size;j++) {
      fprintf(stderr, "%02x", share->hmac[j]);
    }
    fprintf(stderr, "\n\n");
  }

  /* wipe sensitive data and free memory */
  gfshare_ctx_free(G);
  safe_free(sharenrs);
  return 0;
}

int unlock_shares(const unsigned char *pass, size_t pass_len, header_data_t *header) {
  int i, err, ret;
  ret = 0;
  for (i = 0; i < header->nshares; i++) {
    share_data_t *share;
    share = &(header->shares[i]);

    assert(share->key == NULL);
    if (share->ptxt == NULL) {
      share->key  = safe_malloc(header->key_size);
      share->ptxt = safe_malloc(header->share_size);

      unsigned long key_size;
      key_size = header->key_size;

      if ((err = pbkdf2(pass, pass_len, share->salt, SALT_SIZE, share->iter,
                        find_hash("sha256"), share->key, &key_size)) != CRYPT_OK) {
        /* on an hmac failure (wrong password) */
        wipe_free(share->key, header->key_size);
        safe_free(share->ptxt); /* should still be unused */
        continue;
      } 
      if ((err = decrypt_data(share->ctxt, share->ptxt, header->share_size,
                              share->key,  header->key_size,
                              share->hmac, header->hmac_size)) == 0) {
        fprintf(stderr, "Unlocked share %d\n", i);
        ret++;
      } else {
        wipe_free(share->ptxt, header->share_size);
      }
      wipe_free(share->key, header->key_size);
    }
  }
  return ret;
}


int tc_gfcombine(header_data_t *header) {
  int i, loaded, err, ret;
  gfshare_ctx *G;
  unsigned char sharenrs[256];
  memset(sharenrs, 0, sizeof(sharenrs));

  err = ret = loaded = 0;
  
  /* Initialize a gfshare context for decoding */
  G = gfshare_ctx_init_dec(sharenrs, header->thresh, header->key_size);

  assert(header->master_key == NULL);

  for (i = 0; i < header->nshares; i++) {
    share_data_t *share;
    share = &(header->shares[i]);
    if (share->ptxt != NULL) {
      sharenrs[loaded] = share->ptxt[0];
      gfshare_ctx_dec_newshares(G, sharenrs);
      gfshare_ctx_dec_giveshare(G, loaded, share->ptxt + 1);
      if (++loaded == header->thresh)
        break;
    }
  }
  header->master_key = safe_malloc(header->key_size);
  gfshare_ctx_dec_extract(G, header->master_key);
  return ret;
}

/* vim: set ts=2 sw=2 et ai si: */
