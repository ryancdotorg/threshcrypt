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
#define BUFFER_SIZE 65536
#define HEADER_SIZE 32768

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

/* file format offset macros */
/* The nested additions should get merged by the compiler */
#define HDR_MAGIC(x)       (x)
#define HDR_VERSION(x)     HDR_MAGIC(x     + 8)
#define HDR_CIPHER(x)      HDR_VERSION(x   + 4)
#define HDR_HASH(x)        HDR_CIPHER(x    + 1)
#define HDR_KDF(x)         HDR_HASH(x      + 1)
#define HDR_NSHARES(x)     HDR_KDF(x       + 1)
#define HDR_THRESH(x)      HDR_NSHARES(x   + 1)
#define HDR_KEY_SIZE(x)    HDR_THRESH(x    + 1)
#define HDR_HMAC_SIZE(x)   HDR_KEY_SIZE(x  + 1)
#define HDR_SHARE_SIZE(x)  HDR_HMAC_SIZE(x + 1)
/* byte 19 */

/* master key info starts at byte 64 */
#define HDR_MASTER_ITER(x) (x + 64)
#define HDR_MASTER_SALT(x) HDR_MASTER_ITER(x + 4)
#define HDR_MASTER_HMAC(x) HDR_MASTER_SALT(x + SALT_SIZE)

/* share start offsets are (n + 1) * 128 bytes */
#define HDR_SHR_ITER(x, n) (x + ((n + 1) << 7))
#define HDR_SHR_SALT(x, n) HDR_SHR_ITER(x + 4, n)
#define HDR_SHR_CTXT(x, n) HDR_SHR_SALT(x + SALT_SIZE, n)
#define HDR_SHR_HMAC(x, n) HDR_SHR_ITER(x + 96, n)
/* end of file format offset macros */

/* File format specification
; global stuff
0x0000: magic[8]
0x0008: version[4]

0x000c: cipher[1]
0x000d: hash[1]
0x000e: nshares[1]
0x000f: thresh[1] // if zero, then figure it out

0x0010: key_size[1]
0x0011: hmac_size[1]
0x0012: share_size[1]

; master key stuff
0x0040: iter[4]
0x0044: salt[12]
0x0050: master_hmac[hmac_size]

share 1..N {
0x(sharen * 0x0080):
+ 0x00: iter[4];
+ 0x0a: salt[12]
+ 0x0e: share_ctxt[share_size]
+ 0x60: share_hmac[hmac_size];
}
*/

// vim: ts=2 sw=2 et ai si
#endif // THRESHCRYPT_COMMON_H_
