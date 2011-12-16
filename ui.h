/* threshcrypt ui.h
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#ifndef THRESHCRYPT_UI_H_
#define THRESHCRYPT_UI_H_

int load_term(struct termios *);
int save_term(struct termios *);

int get_pass(char *, uint8_t, const char *, const char *, const char *, int);

/* vim: set ts=2 sw=2 et ai si: */
#endif /* THRESHCRYPT_UI_H_ */
