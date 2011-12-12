/* threshcrypt file.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESCRYPT_FILE_H_
#define THRESCRYPT_FILE_H_

int parse_header(unsigned char *, header_data_t *);
int write_header(header_data_t *, int);

// vim: ts=2 sw=2 et ai si
#endif//THRESCRYPT_FILE_H_
