/* threshcrypt util.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESCRYPT_UTIL_H_
#define THRESCRYPT_UTIL_H_

#define KEYMEM_SIZE 49152 /* 48kb */

void * safe_malloc(size_t);

#ifndef HAS_MEMSET_S
int memset_s(void *, size_t, int, size_t);
#endif

#define safe_free(ptr) _safe_free((void **) &ptr, __FILE__, __LINE__)
void _safe_free(void **, const char *, int);

#define wipe_free(ptr, size) _wipe_free((void **) &ptr, size, __FILE__, __LINE__)
void _wipe_free(void **, size_t, const char *, int);

/* security critical memory wipe */
#define MEMWIPE(p, s)      memset_s(p, s, 0x33, s)
#define MEMWIPE_V(p, s, v) memset_s(p, s, v, s)

/* non-security memory zero */
#define MEMZERO(p, s) memset(p, 0, s)

void memxor(unsigned char *, const unsigned char *, size_t);

void fill_rand(unsigned char *, unsigned int);
void fill_prng(unsigned char *, unsigned int);

void free_header(header_data_t *);
void wipe_shares(header_data_t *);

void keymem_init(keymem_t *);
void keymem_wipe(keymem_t *);
void keymem_destroy(keymem_t *);
void * keymem_alloc(keymem_t *, size_t);

void * sec_malloc(size_t);
#define sec_free(ptr) _sec_free((void **) &ptr)
void _sec_free(void **);

/* vim: set ts=2 sw=2 et ai si: */
#endif /* THRESCRYPT_UTIL_H_ */
