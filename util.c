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
#include <unistd.h>

#include <tomcrypt.h>

#include "common.h"
#include "util.h"

void * safe_malloc(size_t size) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    perror("malloc");
    fprintf(stderr, "malloc(%ud) returned NULL\n", (unsigned int)size);
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

void keymem_init(keymem_t *keymem) {
  assert(keymem != NULL);
  int pagesize = sysconf(_SC_PAGESIZE);
  if (keymem->ptr != NULL) {
    fprintf(stderr, "Warning: Tried to re-initialize keymem\n");
    return;
  }
  /* Set up page aligned memory */
  keymem->ptr = safe_malloc(SECMEM_SIZE + pagesize); /* we rely on this being zero filled */
  if ((long)(keymem->ptr) % pagesize == 0) {
    keymem->off = 0;
  } else {
    keymem->off = ((((long)(keymem->ptr) & ~(pagesize-1)) + pagesize) - (long)(keymem->ptr));
  }
  keymem->pos = 0;
  keymem->lck = 0;
  keymem->len = SECMEM_SIZE;
  /* fprintf(stderr, "keymem_init: %p + %d\n", keymem->ptr, keymem->off); */
}

/* There are no corrosponding 'free' or 'realloc' functions. */
void * keymem_alloc(keymem_t *keymem, size_t size) {
  assert(keymem != NULL);
  int pagesize = sysconf(_SC_PAGESIZE);
  if (keymem->ptr == NULL) {
    keymem_init(keymem);
  }
  void *ptr = keymem->ptr + keymem->off + keymem->pos;
  /* verify we have enough remaining space for the requested allocation */
  if ((keymem->pos += size) > keymem->len) {
    fprintf(stderr, "keymem_alloc: could not allocate %d bytes\n", (unsigned int)size);
    exit(EXIT_FAILURE);
  }
#ifdef _POSIX_MEMLOCK_RANGE
  while (keymem->pos + size > keymem->lck) {
    /* fprintf(stderr, "keymem_alloc: locking %d bytes @ %p+0x%04x\n", pagesize, keymem->ptr + keymem->off, keymem->lck); DEBUG */
    if (mlock(keymem->ptr + keymem->off + keymem->lck, pagesize) != 0) {
      fprintf(stderr, "keymem_alloc: could not lock %d bytes (%d already locked)\n", pagesize, keymem->lck);
      perror("");
    } else {
      keymem->lck += pagesize;
    }
  }
#endif
  MEMZERO(ptr, size);
  /* fprintf(stderr, "keymem_alloc: %p-%p\n", ptr, (char *)ptr + size - 1); */
  return ptr;
}

void keymem_wipe(keymem_t *keymem) {
  assert(keymem != NULL);
  if (keymem->ptr != NULL) {
    memset(keymem->ptr + keymem->off, 0x55, keymem->len);
#ifdef _POSIX_MEMLOCK_RANGE
    if (keymem->lck > 0) {
      munlock(keymem->ptr + keymem->off, keymem->lck);
    }
#endif
  }
  /* reset position markers */
  keymem->pos = 0;
  keymem->lck = 0;
}

void keymem_destroy(keymem_t *keymem) {
  keymem_wipe(keymem);
  if (keymem->ptr != NULL) {
    free(keymem->ptr);
  }
  /* clear everything else */
  keymem->ptr = NULL;
  keymem->off = 0;
  keymem->len = 0; 
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
    if (header->keymem != NULL)
      keymem_destroy(header->keymem);
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
