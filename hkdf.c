#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <tomcrypt.h>

#include "hkdf.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b))?(a):(b)
#endif

/* This is mostly just a wrapper around hmac_memory */
int hkdf_extract(int hash_idx, const unsigned char *salt, unsigned long  saltlen,
                               const unsigned char *in,   unsigned long  inlen,
                                     unsigned char *out,  unsigned long *outlen) {
  int ret;
  /* libtomcrypt chokes on a zero length HMAC key, so we need to check for
     that.  HMAC specifies that keys shorter than the hash's blocksize are
     0 padded to the block size.  HKDF specifies that a NULL salt is to be
     substituted with a salt comprised of hashLen 0 bytes.  HMAC's padding
     means that in either case the HMAC is actually using a blocksize long
     zero filled key.  Unless blocksize < hashLen (which wouldn't make any
     sense), we can use a single 0 byte as the HMAC key and still generate
     valid results for HKDF. */
  if (salt == NULL || saltlen == 0) {
    saltlen = hash_descriptor[hash_idx].hashsize;
    ret = hmac_memory(hash_idx, "",   1,       in, inlen, out, outlen); 
  } else {
    ret = hmac_memory(hash_idx, salt, saltlen, in, inlen, out, outlen);
  }
  return ret;
}

int hkdf_expand(int hash_idx, const unsigned char *in,   unsigned long inlen,
                              const unsigned char *info, unsigned long infolen,
                                    unsigned char *out,  unsigned long outlen) {
  const unsigned long hashsize = hash_descriptor[hash_idx].hashsize;
  int err;
  unsigned char N;
  unsigned long outoff;

  unsigned char *T;
  unsigned long Tlen;

  if (inlen < hashsize || outlen > hashsize * 255)
    return CRYPT_INVALID_ARG;
  if (info == NULL && infolen != 0)
    return CRYPT_INVALID_ARG;
  assert(out != NULL);

  Tlen = hashsize + infolen + 1;
  T = XMALLOC(Tlen);
  if (T == NULL) {
    return CRYPT_MEM;
  }

  N = 1;
  outoff = 0; /* offset in out to write to */
  while (outoff < outlen) {
    unsigned long Noutlen = MIN(hashsize, outlen - outoff);
    T[Tlen - 1] = N;
    if (N == 1) {
      XMEMCPY(T + hashsize, info, infolen);
      /* T(1) doesn't include a previous hash value */ 
      if ((err = hmac_memory(hash_idx, in, inlen,
                             T + hashsize, Tlen - hashsize,
                             out + outoff, &Noutlen)) != CRYPT_OK) {
        XMEMSET(T, 0, Tlen); /* wipe */
        XFREE(T);
        return err;
      }
    } else {
      XMEMCPY(T, out + hashsize * (N-2), hashsize);
      if ((err = hmac_memory(hash_idx, in, inlen, T, Tlen,
                             out + outoff, &Noutlen)) != CRYPT_OK) {
        XMEMSET(T, 0, Tlen); /* wipe */
        XFREE(T);
        return err;
      }
    }
    outoff += Noutlen;
    N++;
  }
  XMEMSET(T, 0, Tlen); /* wipe */
  XFREE(T);
  return CRYPT_OK;
}

/* all in one step */
int hkdf(int hash_idx, const unsigned char *salt, unsigned long saltlen,
                       const unsigned char *in,   unsigned long inlen,
                       const unsigned char *info, unsigned long infolen,
                             unsigned char *out,  unsigned long outlen) {
  unsigned long hashsize = hash_descriptor[hash_idx].hashsize;
  int err;
  unsigned char *extracted = XMALLOC(hashsize);
  if (extracted == NULL) {
    return CRYPT_MEM;
  }
  if ((err = hkdf_extract(hash_idx, salt, saltlen, in, inlen, extracted, &hashsize)) != 0) {
    XMEMSET(extracted, 0, hashsize); /* wipe */
    XFREE(extracted);
    return err;
  }
  err = hkdf_expand(hash_idx, extracted, hashsize, info, infolen, out, outlen);
  XMEMSET(extracted, 0, hashsize);  /* wipe */
  XFREE(extracted);
  return err;
}


/* vim: set ts=2 sw=2 et ai si: */
