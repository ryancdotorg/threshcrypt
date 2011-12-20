/* threshcrypt util.c
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

void * safe_malloc(size_t size) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    perror("malloc");
    fprintf(stderr, "malloc(%d) returned NULL\n", (unsigned int)size);
    exit(EXIT_FAILURE);
  }
  memset(ptr, 0, size);
  return ptr;
}

void _safe_free(void **ptr, const char *file, int line) {
  if (*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  } else {
    fprintf(stderr, "Warning: [file %s, line %d]: called safe_free on a null pointer\n", file, line);
  }
}

void _wipe_free(void **ptr, size_t size, const char *file, int line) {
  if (*ptr != NULL) {
    memset(*ptr, 0, size);
    free(*ptr);
    *ptr = NULL;
  } else {
    fprintf(stderr, "Warning: [file %s, line %d]: called wipe_free on a null pointer\n", file, line);
  }
}

void memxor(unsigned char *p1, const unsigned char *p2, size_t size) {
  size_t i = 0;
  for (i = 0;i < size;i++) {
    p1[i] ^= p2[i];
  }
}

void fill_rand(unsigned char *buffer,
               unsigned int count) {
  size_t n;

#if defined(LTC_DEVRANDOM) && defined(TRY_URANDOM_FIRST)
  FILE *devrandom;
  devrandom = fopen("/dev/random", "rb");
  if (!devrandom) {
    fprintf(stderr, "WARNING: Unable to access /dev/random\n");
#endif
    if ((n = rng_get_bytes(buffer, count, NULL)) < count) {
      fprintf(stderr, "Short read from rng; requested %d bytes, got %zd bytes\n", count, n);
      exit(EXIT_FAILURE);
    }
#if defined(LTC_DEVRANDOM) && defined(TRY_URANDOM_FIRST)
  } else {
    n = fread(buffer, 1, count, devrandom);
    if (n < count) {
      perror("Short read from /dev/random");
      exit(EXIT_FAILURE);
    }
  }
#endif
}

void fill_prng(unsigned char *buffer,
               unsigned int count) {
  extern prng_state prng;
  size_t n;

  if ((n = fortuna_read(buffer, count, &prng)) < count) {
    fprintf(stderr, "Short read from prng; requested %d bytes, got %zd bytes\n", count, n);
    exit(EXIT_FAILURE);
  }
}

/* Free header memory, wiping sensitive parts */
void free_header(header_data_t *header) {
  int i;

  if (header != NULL) {
    if (header->shares != NULL) {
      /* wipe/free pointers within each share */
      for (i = 0; i < header->nshares;i++) {
        share_data_t *share;
        share = &(header->shares[i]);

        if (share->key != NULL)
          wipe_free(share->key, header->key_size);
        if (share->ptxt != NULL)
          wipe_free(share->ptxt, header->share_size);
        if (share->ctxt != NULL)
          safe_free(share->ctxt);
        if (share->hmac != NULL)
          safe_free(share->hmac);
      }
      /* free memory from shares */
      safe_free(header->shares);
    }
    if (header->master_key != NULL)
      wipe_free(header->master_key, header->key_size);
    if (header->master_hmac != NULL)
      safe_free(header->master_hmac);
  }
}

void wipe_shares(header_data_t *header) {
  int i;

  if (header != NULL && header->shares != NULL) {
    /* wipe/free pointers within each share */
    for (i = 0; i < header->nshares;i++) {
      share_data_t *share;
      share = &(header->shares[i]);

      if (share->key != NULL)
        wipe_free(share->key, header->key_size);
      if (share->ptxt != NULL)
        wipe_free(share->ptxt, header->share_size);
    }
  }
}

/* vim: set ts=2 sw=2 et ai si: */
