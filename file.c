/* threshcrypt file.c
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include <tomcrypt.h>

#include "common.h"
#include "util.h"
#include "file.h"

/* buf should be a 32768+ byte buffer containing header data from a file */
int parse_header(unsigned char *buf, header_data_t *header) {
  unsigned char magic[THRCR_MAGIC_LEN]     = THRCR_MAGIC;
  /*unsigned char version[THRCR_VERSION_LEN] = THRCR_VERSION;*/

  share_data_t *share;

  /* Check if the data starts with our magic before attempting to parse */
  if (memcmp(HDR_MAGIC(buf), magic, THRCR_MAGIC_LEN))
    return 1; /* no magic */
  
  /* Identification data */
  memcpy(header->magic,         HDR_MAGIC(buf),      THRCR_MAGIC_LEN); 
  memcpy(header->version,       HDR_VERSION(buf),    THRCR_VERSION_LEN);

  /* Parameter data */
  memcpy(&(header->cipher),     HDR_CIPHER(buf),     1);
  memcpy(&(header->hash),       HDR_HASH(buf),       1);
  memcpy(&(header->nshares),    HDR_NSHARES(buf),    1);
  memcpy(&(header->thresh),     HDR_THRESH(buf),     1);
  memcpy(&(header->key_size),   HDR_KEY_SIZE(buf),   1);
  memcpy(&(header->hmac_size),  HDR_HMAC_SIZE(buf),  1);
  memcpy(&(header->share_size), HDR_SHARE_SIZE(buf), 1);
  
  /* Sanity check some critical values */
  if (header->key_size   > 64 || header->hmac_size   > 32 ||
      header->share_size > 80 || header->nshares     <  2 ||
      header->thresh < 2 || header->thresh > header->nshares)
    return 2; /* bad data */

  header->master_hmac = safe_malloc(header->hmac_size);
  header->shares      = safe_malloc(header->nshares * sizeof(share_data_t));

  /* Master key data */
  LOAD32H(header->master_iter, HDR_MASTER_ITER(buf));
  memcpy(header->master_salt, HDR_MASTER_SALT(buf), SALT_SIZE);
  memcpy(header->master_hmac, HDR_MASTER_HMAC(buf), header->hmac_size);

  uint8_t i;
  /* Share data */
  for (i = 0; i < header->nshares; i++) {
    share = &(header->shares[i]);

    share->ctxt = safe_malloc(header->share_size);
    share->hmac = safe_malloc(header->hmac_size);

    LOAD32H(share->iter, HDR_SHR_ITER(buf, i));
    memcpy(share->salt, HDR_SHR_SALT(buf, i), SALT_SIZE);
    memcpy(share->ctxt, HDR_SHR_CTXT(buf, i), header->share_size);
    memcpy(share->hmac, HDR_SHR_HMAC(buf, i), header->hmac_size);
  }

  return 0;
}

int write_header(header_data_t *header, int fd) {
  unsigned char buf[HEADER_SIZE];

  /* zero it - don't want to leak uninitialized memory */
  memset(buf, 0, HEADER_SIZE);

  /* Identification data */
  memcpy(HDR_MAGIC(buf),        header->magic,       8);
  memcpy(HDR_VERSION(buf),      header->version,     4);

  /* Parameter data */
  memcpy(HDR_CIPHER(buf),     &(header->cipher),     1);
  memcpy(HDR_HASH(buf),       &(header->hash),       1);
  memcpy(HDR_NSHARES(buf),    &(header->nshares),    1);
  memcpy(HDR_THRESH(buf),     &(header->thresh),     1);
  memcpy(HDR_KEY_SIZE(buf),   &(header->key_size),   1);
  memcpy(HDR_HMAC_SIZE(buf),  &(header->hmac_size),  1);
  memcpy(HDR_SHARE_SIZE(buf), &(header->share_size), 1);

  /* Master key data */
  STORE32H(header->master_iter, HDR_MASTER_ITER(buf));
  memcpy(HDR_MASTER_SALT(buf), header->master_salt, SALT_SIZE);
  memcpy(HDR_MASTER_HMAC(buf), header->master_hmac, header->hmac_size);

  uint8_t i;
  /* Share data */
  for (i = 0; i < header->nshares; i++) {
    share_data_t *share = &(header->shares[i]);
    STORE32H(share->iter, HDR_SHR_ITER(buf, i));
    memcpy(HDR_SHR_SALT(buf, i), share->salt, SALT_SIZE);
    memcpy(HDR_SHR_CTXT(buf, i), share->ctxt, header->share_size);
    memcpy(HDR_SHR_HMAC(buf, i), share->hmac, header->hmac_size);
  }

  if (write(fd, buf, HEADER_SIZE) < HEADER_SIZE) {
    fprintf(stderr, "Short fwrite on header\n");
    return -1;
  }

  return 0;
}

/* vim: set ts=2 sw=2 et ai si: */
