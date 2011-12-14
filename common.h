/* threshcrypt common.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESHCRYPT_COMMON_H_
#define THRESHCRYPT_COMMON_H_

#define FILE_MAGIC   0x6be114190fe1a015ULL
#define FILE_VERSION 0x00000001U

#define MODE_UNKNOWN 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

#define DEFAULT_ITERATIONS 31337
#define DEFAULT_SHARECOUNT 3
#define DEFAULT_THRESHOLD  2
#define DEFAULT_KEY_BITS   256

#define SUBKEY_ITER 16

#define SALT_SIZE 12
#define HMAC_SIZE 16
#define HEADER_SIZE 32768
#define BUFFER_SIZE 65536

#define pbkdf2 pkcs_5_alg2

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

// vim: ts=2 sw=2 et ai si
#endif // THRESHCRYPT_COMMON_H_
