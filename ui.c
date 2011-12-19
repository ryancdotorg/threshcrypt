/* threshcrypt ui.c
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 */

#include <termios.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "ui.h"

int load_term(struct termios *termios_p) {
  if (tcsetattr(fileno(stdin), TCSANOW, termios_p) != 0) {
    fprintf(stderr, "Failed to load terminal settings");
    return -1;
  }
  return 0;
}

int save_term(struct termios *termios_p) {
    if (tcgetattr(fileno(stdin), termios_p) != 0) {
      fprintf(stderr, "Failed to save terminal settings");
      return -1;
    }
  return 0;
}

int get_pass(char *pass, uint8_t pass_size, const char *prompt,
             const char *vprompt, const char *rprompt, int verify) {
  struct termios old_term, new_term;
  uint8_t i, j;
  int chr;
  char vpass[256];

  assert(pass_size > 1);
  do {
    if (save_term(&old_term) != 0) {
      return -1;
    }
    new_term = old_term;
    fprintf(stderr, "%s", prompt);
    /* Turn off echo */
    new_term.c_lflag &= ~ECHO;
    if (load_term(&new_term) != 0) {
      return -1;
    }

    i = 0;
    while (i < pass_size - 1) {
      chr = getchar();
      if (chr >= 32 && chr <= 126) {
        pass[i] = chr;
        i++;
      } else if (chr == '\b' && i > 0) { /* backspace */
        pass[i] = '\0';
        i--;
      } else if (chr == '\n') {
        pass[i] = '\0';
        break;
      }
    }
    /* restore echo */
    if (load_term(&old_term) != 0) {
      return -1;
    }
    if (vprompt != NULL) {
      fprintf(stderr, "\033[0G\033[2K");
      j = get_pass(vpass, pass_size, vprompt, NULL, NULL, 0);
      if (j != i || memcmp(pass, vpass, i) != 0) {
        memset(vpass, 0, sizeof(vpass));
        memset(pass,  0, sizeof(pass));
        if (verify > 1) {
          fprintf(stderr, "%s\n", rprompt);
          verify--;
        } else {
          return -1;
        }
      } else {
        memset(vpass, 0, sizeof(vpass));
        assert(i == j);
        assert(i == strlen(pass));
        return i;
      }
    } else {
      break;
    }
  } while (verify > 0);
  fprintf(stderr, "\n");
  return i;
}
/* vim: set ts=2 sw=2 et ai si: */
