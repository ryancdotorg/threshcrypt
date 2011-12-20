/* threshcrypt common.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESHCRYPT_COMMON_H_
#define THRESHCRYPT_COMMON_H_

#define THRCR_VERSION_STR "0.0.1.0" 

#define MODE_UNKNOWN 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

#define DEFAULT_ITERATIONS 31337
#define DEFAULT_SHARECOUNT     3
#define DEFAULT_THRESHOLD      2
#define DEFAULT_KEY_BITS     256

#define MAX_ITER_MS   60000
#define MAX_KEY_SIZE     64
#define MAX_HMAC_SIZE    32
#define MAX_SHARE_SIZE   72

#define SUBKEY_ITER      16

#define SALT_SIZE        12
#define HMAC_SIZE        16

#define HEADER_SIZE   32768
#define BUFFER_SIZE   65536

/* return codes */
#define THRCR_OK          0
#define THRCR_ERROR       1
#define THRCR_NOMAGIC     2
#define THRCR_BADMODE     3
#define THRCR_BADDATA     4
#define THRCR_BADMAC      5
#define THRCR_ENCERR      6
#define THRCR_DECERR      7
#define THRCR_IOERR       8
#define THRCR_READERR     9
#define THRCR_WRITEERR   10

/* macro functions */
#define pbkdf2(p, pl, s, ss, i, h, k, ks) \
        pkcs_5_alg2(p, pl, s, ss, i, h, k, (unsigned long *)ks)

#ifndef MIN
#define MIN(a,b) ((a)<(b))?(a):(b)
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b))?(a):(b)
#endif


typedef struct {
	unsigned char *key;  /* SENSITIVE */
	unsigned char *ptxt; /* SENSITIVE */
	int32_t iter;
	unsigned char salt[SALT_SIZE];
	unsigned char *ctxt;
	unsigned char *hmac;
} share_data_t;

typedef struct {
  unsigned char *master_key; /* SENSITIVE */
	unsigned char magic[8];
	unsigned char version[4];
	uint8_t cipher;
	uint8_t hash;
	uint8_t kdf;
	uint8_t nshares;
	uint8_t thresh;
  /* all sizes in bytes */
	uint8_t key_size;
	uint8_t hmac_size;
	uint8_t share_size;
	int32_t master_iter;
	unsigned char master_salt[SALT_SIZE];
	unsigned char *master_hmac;
	share_data_t *shares;
} header_data_t;

/* vim: set ts=2 sw=2 et ai si: */
#endif /* THRESHCRYPT_COMMON_H_ */
