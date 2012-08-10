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

/* util.h: #define safe_free(ptr) _safe_free((void **) &ptr, __FILE__, __LINE__) */
void _safe_free(void **ptr, const char *file, int line) {
  if (*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  } else {
    fprintf(stderr, "Warning: [file %s, line %d]: called safe_free on a null pointer\n", file, line);
  }
}

/* util.h: #define wipe_free(ptr, size) _wipe_free((void **) &ptr, size, __FILE__, __LINE__) */
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

/* for non-key secret data - can be freed */
void * sec_malloc(size_t size) {
  assert(sizeof(long) >= sizeof(void *));
  int pagesize      = sysconf(_SC_PAGESIZE);
  int metadata_size = sizeof(void *) + sizeof(size_t);

  /* pad size up to an increment of pagesize if needed */
  if (size % pagesize != 0)
    size = (size + pagesize) & ~(pagesize-1);

  void    *main_ptr = safe_malloc(metadata_size + size + pagesize);
  void    *data_ptr = (void *)((long)main_ptr + metadata_size);
  size_t  *size_ptr;
  void   **base_ptr;

  /* check if it's already aligned */
  if ((long)(data_ptr) % pagesize != 0)
    /* move up data_ptr to the next page boundry */
    data_ptr = (void *)((((long)(data_ptr) & ~(pagesize-1)) + pagesize));

/* prevent swapping of this memory if possible */
#ifdef _POSIX_MEMLOCK_RANGE
  if (mlock(data_ptr, size) != 0) {
    fprintf(stderr, "sec_malloc: could not lock %zu bytes\n", size);
    perror("");
  }
#endif

  /* save the locked memory size so we can wipe it later */
  size_ptr  = (void *)((long)data_ptr - sizeof(size_t));
  *size_ptr = size;
  /* save the base pointer so we can free it later */
  base_ptr  = (void *)((long)data_ptr - metadata_size);
  *base_ptr = main_ptr;

/*fprintf(stderr, " main_ptr: %p\n", main_ptr);
  fprintf(stderr, " data_ptr: %p\n", data_ptr);
  fprintf(stderr, " size_ptr: %p\n", (void *)size_ptr);
  fprintf(stderr, " base_ptr: %p\n", (void *)base_ptr);
  fprintf(stderr, "*base_ptr: %p\n", *base_ptr);
  fprintf(stderr, "*size_ptr: %zu\n", *size_ptr);
  fprintf(stderr, " size:     %zu\n", size);*/
  return data_ptr;
}

/* util.h: #define sec_free(ptr) _sec_free((void **) &ptr) */
void _sec_free(void ** data_ptr) {
  assert(sizeof(long) >= sizeof(void *));
  assert(data_ptr != NULL);
  if (*data_ptr == NULL) {
    fprintf(stderr, "Warning: attempted double _sec_free\n");
    return;
  }

  int metadata_size = sizeof(void *) + sizeof(size_t);

  void  **base_ptr;
  size_t *size_ptr;

  /* load the locked allocation size */
  size_ptr = (void *)((long)*data_ptr - sizeof(size_t));
  /* load the base pointer */
  base_ptr = (void *)((long)*data_ptr - metadata_size);

/*fprintf(stderr, " data_ptr: %p\n", *data_ptr);
  fprintf(stderr, " size_ptr: %p\n", (void *)size_ptr);
  fprintf(stderr, " base_ptr: %p\n", (void *)base_ptr);
  fprintf(stderr, "*base_ptr: %p\n", *base_ptr);
  fprintf(stderr, "*size_ptr: %zu\n", *size_ptr);*/
  
  MEMWIPE(*data_ptr, *size_ptr);
  *data_ptr = NULL;

  if (*base_ptr != NULL) {
    void *tmp_ptr = *base_ptr;
    /* We could clear *base_ptr after the free to save a few instructions, but
       doing that makes memory checkers angry */
    *base_ptr = NULL;
    free(tmp_ptr);
  } else {
    fprintf(stderr, "Fatal: attempted partial double _sec_free\n");
    exit(EXIT_FAILURE);
  }
}

void keymem_init(keymem_t *keymem) {
  assert(keymem != NULL);
  assert(sizeof(long) == sizeof(void *));
  int pagesize = sysconf(_SC_PAGESIZE);
  if (keymem->ptr != NULL) {
    fprintf(stderr, "Warning: Tried to re-initialize keymem\n");
    return;
  }
  /* Set up page aligned memory */
  keymem->ptr = safe_malloc(KEYMEM_SIZE + pagesize); /* we rely on this being zero filled */
  if ((long)(keymem->ptr) % pagesize == 0) {
    keymem->off = 0;
  } else {
    keymem->off = ((((long)(keymem->ptr) & ~(pagesize-1)) + pagesize) - (long)(keymem->ptr));
  }
  keymem->pos = 0;
  keymem->lck = 0;
  keymem->len = KEYMEM_SIZE;
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
      fclose(devrandom);
      exit(EXIT_FAILURE);
    }
    fclose(devrandom);
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
    if (header->keymem != NULL) {
      keymem_destroy(header->keymem);
      safe_free(header->keymem);
    }
    if (header->shares != NULL) {
      int i;
      for (i = 0; i < header->nshares;i++) {
        share_data_t *share;
        share = &(header->shares[i]);
        if (share->ctxt != NULL)
          safe_free(share->ctxt);
        if (share->hmac != NULL)
          safe_free(share->hmac);
      }
      safe_free(header->shares);
    }
    if (header->master_hmac != NULL)
      safe_free(header->master_hmac);
  }
  safe_free(header);
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
