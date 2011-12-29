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

/* for mlock */
#include <sys/mman.h>
#include <limits.h>

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
  MEMZERO(ptr, size);
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
    MEMWIPE(*ptr, size);
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

void secmem_init(secmem_t *secmem) {
  assert(secmem != NULL);
  int pagesize = sysconf(_SC_PAGESIZE);
  if (secmem->ptr != NULL) {
    fprintf(stderr, "Warning: Tried to re-initialize secmem\n");
    return;
  }
  /* Set up page aligned memory */
  secmem->ptr = safe_malloc(SECMEM_SIZE + pagesize); /* we rely on this being zero filled */
  if ((long)(secmem->ptr) % pagesize == 0) {
    secmem->off = 0;
  } else {
    secmem->off = ((((long)(secmem->ptr) & ~(pagesize-1)) + pagesize) - (long)(secmem->ptr));
  }
  secmem->pos = 0;
  secmem->lck = 0;
  secmem->len = SECMEM_SIZE;
  /* fprintf(stderr, "secmem_init: %p + %d\n", secmem->ptr, secmem->off); */
}

/* There are no corrosponding 'free' or 'realloc' functions. */
void * secmem_alloc(secmem_t *secmem, size_t size) {
  assert(secmem != NULL);
  int pagesize = sysconf(_SC_PAGESIZE);
  if (secmem->ptr == NULL) {
    secmem_init(secmem);
  }
  void *ptr = secmem->ptr + secmem->off + secmem->pos;
  /* verify we have enough remaining space for the requested allocation */
  if ((secmem->pos += size) > secmem->len) {
    fprintf(stderr, "secmem_alloc: could not allocate %d bytes\n", (unsigned int)size);
    exit(EXIT_FAILURE);
  }
#ifdef _POSIX_MEMLOCK_RANGE
  while (secmem->pos + size > secmem->lck) {
    /* fprintf(stderr, "secmem_alloc: locking %d bytes @ %p+0x%04x\n", pagesize, secmem->ptr + secmem->off, secmem->lck); DEBUG */
    if (mlock(secmem->ptr + secmem->off + secmem->lck, pagesize) != 0) {
      fprintf(stderr, "secmem_alloc: could not lock %d bytes (%d already locked)\n", pagesize, secmem->lck);
      perror("");
    } else {
      secmem->lck += pagesize;
    }
  }
#endif
  MEMZERO(ptr, size);
  /* fprintf(stderr, "secmem_alloc: %p-%p\n", ptr, (char *)ptr + size - 1); */
  return ptr;
}

void secmem_wipe(secmem_t *secmem) {
  assert(secmem != NULL);
  if (secmem->ptr != NULL) {
    memset(secmem->ptr + secmem->off, 0x55, secmem->len);
#ifdef _POSIX_MEMLOCK_RANGE
    if (secmem->lck > 0) {
      munlock(secmem->ptr + secmem->off, secmem->lck);
    }
#endif
  }
  /* reset position markers */
  secmem->pos = 0;
  secmem->lck = 0;
}

void secmem_destroy(secmem_t *secmem) {
  secmem_wipe(secmem);
  if (secmem->ptr != NULL) {
    free(secmem->ptr);
  }
  /* clear everything else */
  secmem->ptr = NULL;
  secmem->off = 0;
  secmem->len = 0; 
}

void fill_rand(unsigned char *buffer,
               unsigned int count) {
  size_t n;

#if defined(LTC_DEVRANDOM) && defined(TRY_URANDOM_FIRST)
  /* Override libtomcrypt's use of /dev/urandom */
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

/* Free header memory */
void free_header(header_data_t *header) {
  if (header != NULL) {
    if (header->secmem != NULL)
      secmem_destroy(header->secmem);
    if (header->shares != NULL)
      safe_free(header->shares);
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
        MEMWIPE(share->key, header->key_size);
      if (share->ptxt != NULL)
        MEMWIPE(share->ptxt, header->share_size);
    }
  }
}

/* vim: set ts=2 sw=2 et ai si: */
