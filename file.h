/* threshcrypt file.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESCRYPT_FILE_H_
#define THRESCRYPT_FILE_H_

int parse_header(unsigned char *, header_data_t *);
int write_header(header_data_t *, int);

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

#define THRCR_MAGIC        {'T','h','r','C','r','\r','\n','\0'}
#define THRCR_MAGIC_LEN    8

#define THRCR_VERSION      {'\0','\0','\0','\1'}
#define THRCR_VERSION_LEN  4

/* file format offset macros */
/* The nested additions should get merged by the compiler */
#define HDR_MAGIC(x)       (x)
#define HDR_VERSION(x)     HDR_MAGIC(x     + THRCR_MAGIC_LEN)
#define HDR_CIPHER(x)      HDR_VERSION(x   + THRCR_VERSION_LEN)
#define HDR_HASH(x)        HDR_CIPHER(x    + 1)
#define HDR_KDF(x)         HDR_HASH(x      + 1)
#define HDR_NSHARES(x)     HDR_KDF(x       + 1)
#define HDR_THRESH(x)      HDR_NSHARES(x   + 1)
#define HDR_KEY_SIZE(x)    HDR_THRESH(x    + 1)
#define HDR_HMAC_SIZE(x)   HDR_KEY_SIZE(x  + 1)
#define HDR_SHARE_SIZE(x)  HDR_HMAC_SIZE(x + 1)
/* byte 20 */

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

/* vim: set ts=2 sw=2 et ai si: */
#endif /* THRESCRYPT_FILE_H_ */
