/* threshcrypt shares.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESHCRYPT_SHARES_H_
#define THRESHCRYPT_SHARES_H_

#define SHARE_KEY  skey_data + (i * key_size)
#define SHARE_SALT salt_data + (i * salt_size)

int do_gfsplit(header_data_t *);
int unlock_shares(unsigned char *, size_t, header_data_t *); 

// vim: ts=2 sw=2 et ai si
#endif // THRESHCRYPT_SHARES_H_
