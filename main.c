/* threshcrypt main.c
 * Copyright 2012 Ryan Castellucci <code@ryanc.org>
 * This software is published under the terms of the Simplified BSD License.
 * Please see the 'COPYING' file for details.
 * Portions of this file are derived from libgfshare examples which are
 * Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006-2011
 */

#include <termios.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/time.h>
#include <time.h>

#include <libgfshare.h>
#include <tomcrypt.h>

#include "common.h"
#include "ui.h"
#include "file.h"
#include "util.h"
#include "crypt.h"
#include "shares.h"
#include "main.h"

struct termios orig_term_set;

static char* progname;

prng_state prng;

void sigint_handle(int sig) {
  if (sig == SIGINT) { load_term(&orig_term_set); fprintf(stderr, "\n"); }
  exit(0);
}

/* Calculate the number of iterations needed to take a given amount of time */
static int pbkdf2_itertime(int hash_idx, size_t size, int msec) {
  struct timeval time1;
  struct timeval time2;

  unsigned char *salt = "Your mother was a hamster...";
  unsigned char *pass = "...and your father smelt of elderberries!";
  unsigned char *buf  = safe_malloc(size);

  int iter = 1617; /* this number is of no significance */
  float duration = 0; /* seconds */
  float spi; /* seconds per iter */

  /* loop until we find a value for iter that takes at least 0.10 seconds */
  while (duration < 0.10) { /* minimum time */
    gettimeofday(&time1, NULL);
    pbkdf2(pass, strlen(pass), salt, strlen(salt), iter, hash_idx, buf, &size);
    gettimeofday(&time2, NULL);
    duration = (time2.tv_sec - time1.tv_sec) + (float)(time2.tv_usec - time1.tv_usec) / 1000000;
    spi = 1000 * duration / iter; /* calculate seconds per iter */
    /*fprintf(stderr, "PBKDF2:%6.3f,%6d,%10.3e\n", duration, iter, spi);*/
    /* set iter to a value expected to take around 0.12 seconds*/
    iter = 0.12 * 1000 / spi;
  }
  safe_free(buf);
  fprintf(stderr, "PBKDF2:%6.3f,%6d\n", (float) msec / 1000, (int)(msec / spi));
  return (int)(msec / spi);
}

void usage(FILE* stream) {
  fprintf(stream, "\
Usage: %s [-c iterations] [-m sharecount] [-n threshold] infile [outfile]\n\
  where sharecount is the number of shares to build.\n\
  where threshold is the number of shares needed to recombine.\n\
\n\
The sharecount option defaults to %d.\n\
The threshold option defaults to %d.\n\
", progname, DEFAULT_SHARECOUNT, DEFAULT_THRESHOLD );
}

#define OPTSTRING "b:i:t:n:m:o:hved"
int main(int argc, char **argv) {
  unsigned int sharecount = DEFAULT_SHARECOUNT;
  unsigned int threshold  = DEFAULT_THRESHOLD;
  unsigned int key_bits   = DEFAULT_KEY_BITS;
           int base_iter  = DEFAULT_ITERATIONS;
           int mode       = MODE_UNKNOWN;

  unsigned char buf[BUFFER_SIZE];

  unsigned int i;
  int ret, err;

  char *in_file, *out_file;
  int in_fd, out_fd;

  char *endptr;
  int optnr;
  
  header_data_t header;
  /* zero the memory of the struct - sets all pointers to NULL */
  memset(&header, 0, sizeof(header));
  
  progname = argv[0];
  /* Seed the PRNG with */
  srandom( time(NULL) ^ (getpid() << (sizeof(int) * 4)) );

  /* Setup fortuna PRNG */
  if (register_prng(&fortuna_desc) == -1) {
    fprintf(stderr, "Error registering Fortuna\n");
    exit(EXIT_FAILURE);
  }

  if ((err = rng_make_prng(128, find_prng("fortuna"), &prng, NULL)) != CRYPT_OK) {
    fprintf(stderr, "Error starting Fortuna: %s\n", error_to_string(err));
    exit(EXIT_FAILURE);
  }

  if ((err = fortuna_ready(&prng)) != CRYPT_OK) {
    fprintf(stderr, "Fortuna not ready: %s\n", error_to_string(err));
    exit(EXIT_FAILURE);
  }
  /* end fortuna setup */

  /* register other tomcrypt algorithms */
  if (register_cipher(&aes_desc) == -1) {
    fprintf(stderr, "Failed to register AES\n");
    exit(EXIT_FAILURE);
  }

  if (register_hash(&sha1_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-1\n");
    exit(EXIT_FAILURE);
  }

  if (register_hash(&sha256_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-256\n");
    exit(EXIT_FAILURE);
  }
  /* end tomcrypt algorithm registration */

  /* Set the prng for gfshare */
  gfshare_fill_rand = fill_prng;

  /* parse command line arguments */
  while( (optnr = getopt(argc, argv, OPTSTRING)) != -1 ) {
    switch( optnr ) {
    case 'v':
      fprintf( stdout, "%s", "\
Copyright 2012 Ryan Castellucci <code@ryanc.org>\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
" );
      return 0;
      break;
    case 'h':
      fprintf(stdout, "threshcrypt\n");
      usage(stdout);
      return 0;
      break;
    case 'e':
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -e, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      break;
    case 'd':
      if (mode == MODE_ENCRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -d, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_DECRYPT;
      break;
    case 'i':
      base_iter = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -i, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if (*endptr != 0 || *optarg == 0 || 
          base_iter < 1024 || base_iter > INT_MAX ) {
          fprintf(stderr, "%s: Invalid argument to option -i (%d)\n", progname, base_iter);
          usage(stderr);
          return 1;
      }
      break;
    case 'b':
      key_bits = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -b, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if (*endptr != 0 || *optarg == 0 || 
          (key_bits != 128 && key_bits != 192 && key_bits != 256) ) {
          fprintf(stderr, "%s: Invalid argument to option -b (%d)\n", progname, key_bits);
          usage(stderr);
          return 1;
      }
      break;
    case 'm':
      sharecount = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -m, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if( *endptr != 0 || *optarg == 0 || 
          sharecount < 2 || sharecount > 255 ) {
        fprintf(stderr, "%s: Invalid argument to option -m (%d)\n", progname, sharecount );
        usage(stderr);
        return 1;
      }
      break;
    case 'n':
      threshold = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -n, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if( *endptr != 0 || *optarg == 0 || threshold < 2) {
        fprintf(stderr, "%s: Invalid argument to option -n (%d)\n", progname, threshold );
        usage(stderr);
        return 1;
      }
      break;
    }
  }

  if (threshold > sharecount) {
    fprintf(stderr, "%s: argument to -m must not be smaller than argument to -n\n", progname);
    usage(stderr);
    return 1;
  }

  /*fprintf(stderr, "%d, %d\n", optind, argc);*/
  if (optind == (argc - 2)) {
    in_file  = argv[optind++];
    out_file = argv[optind++];
  } else if (optind == (argc - 1)) {
    in_file  = argv[optind++];
    out_file = NULL;
  } else {
    fprintf(stderr, "%s: Bad argument count\n", progname);
    usage(stderr);
    return 1;
  }
  /* end command line argument parsing */

  /* some initialization */
  if ((in_fd = open(in_file, O_RDONLY)) < 0) {
    fprintf(stderr, "%s: Failed to open '%s' for reading: ", progname, in_file);
    perror("");
    exit(EXIT_FAILURE);
  }

  if (mode == MODE_UNKNOWN)
    mode = MODE_DECRYPT;

  save_term(&orig_term_set);
  signal(SIGINT, sigint_handle);

  size_t key_size = key_bits / 8;
  size_t salt_size = SALT_SIZE;
  size_t hmac_size = HMAC_SIZE;
  size_t share_size = key_size + 1;

  unsigned char pass[256];
  unsigned char prompt[64];
  unsigned char vprompt[64];
  int pass_ret, hash_idx;

  hash_idx = find_hash("sha256");  
  if (mode == MODE_DECRYPT) {
    /* Read in what we hope is a threshcrypt header */
    if (read(in_fd, buf, HEADER_SIZE) < HEADER_SIZE) {
      /* Not a threshcrypt file - too small */
      fprintf(stderr, "%s: Error reading header of '%s': too small\n", progname, in_file);
      exit(EXIT_FAILURE);
    }
    if ((err = parse_header(buf, &header)) != 0) {
      switch(err) {
        case 1:
          fprintf(stderr, "%s: Error reading header of '%s': no magic\n", progname, in_file);
          break;
        case 2:
          fprintf(stderr, "%s: Error reading header of '%s': bad data\n", progname, in_file);
          break;
      }
    }

    /* unlock shares */
    int unlocked = 0;
    while (unlocked < header.thresh) {
      fprintf(stderr, "More passwords are required to meet decryption threshold.\n");
      snprintf( prompt, 64, "Enter any remaining share password [%d/%d]: ", unlocked, header.thresh);
      pass_ret = get_pass(pass, 128, prompt, NULL, NULL, 0);
      if (pass_ret < 0) {
        fprintf(stderr, "Password entry failed.\n");
        exit(EXIT_FAILURE);
      } else if (pass_ret < 1) {
        fprintf(stderr, "Password must be at least one character(s)\n");
      } else {
        assert(pass_ret == (int)strlen(pass));

        int unlock_ret;
        if ((unlock_ret = unlock_shares(pass, pass_ret, &header))){
          unlocked += unlock_ret;
          if (unlock_ret == 1) {
            fprintf(stderr, "Password accepted for 1 additional share.\n");
          } else {
            fprintf(stderr, "Password accepted for %d additional shares.\n", unlock_ret);
          }
        }
        memset(pass, 0, sizeof(pass));
      }
    }
    /* Recover master key */
    tc_gfcombine(&header);

    assert(header.master_key != NULL);
    /* verify master key */

    /* open output file */
    if (out_file != NULL) {
      if ((out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
        fprintf(stderr, "%s: Failed to open '%s' for writing: ", progname, out_file);
        perror("");
        exit(EXIT_FAILURE);
      }
    } else {
      out_fd = fileno(stdout);
    }

    /* decrypt data */
    ssize_t len;
    unsigned char *IV = NULL;
    while ((len = read(in_fd, buf, 4)) > 0) {
      uint32_t dlen;
      unsigned char blkmac[32];
      /*unsigned char blkdat[BUFFER_SIZE];*/
      if (len < 4) {
        fprintf(stderr, "%s: Error: short read of blocklen in '%s'\n", progname, in_file);
        exit(EXIT_FAILURE);
      }
      LOAD32H(dlen, buf);
      if (dlen > sizeof(buf)) {
        fprintf(stderr, "%s: Error: blocklen larger than BUFFER_SIZE: '%s'\n", progname, in_file);
        exit(EXIT_FAILURE);
      }
      if ((len = read(in_fd, buf, dlen)) < (ssize_t)dlen) {
        fprintf(stderr, "%s: Error: short read of blockdat in '%s'\n", progname, in_file);
        exit(EXIT_FAILURE);
      }
      if ((len = read(in_fd, blkmac, header.hmac_size)) < header.hmac_size) {
        fprintf(stderr, "%s: Error: short read of blockmac in '%s'\n", progname, in_file);
        exit(EXIT_FAILURE);
      }
      assert(header.master_key != NULL);
      decrypt_block(buf, buf, dlen,
                    header.master_key, header.key_size,
                    blkmac, header.hmac_size, IV);
      write(out_fd, buf, dlen);
    }
    free_header(&header);
    exit(EXIT_SUCCESS);
  }

  if (mode == MODE_ENCRYPT) {
    unsigned char magic[THRCR_MAGIC_LEN]     = THRCR_MAGIC;
    unsigned char version[THRCR_VERSION_LEN] = THRCR_VERSION;

    memcpy(header.magic,   magic,   THRCR_MAGIC_LEN);
    memcpy(header.version, version, THRCR_VERSION_LEN);
    header.cipher      = 1; /* Hardcoded for now */
    header.hash        = 1; /* Hardcoded for now */
    header.kdf         = 1; /* Hardcoded for now */
    header.nshares     = sharecount;
    header.thresh      = threshold;
    header.key_size    = key_size;
    header.hmac_size   = hmac_size;
    header.share_size  = share_size;
    header.master_iter = SUBKEY_ITER;
    header.master_hmac = safe_malloc(hmac_size);
    header.master_key  = safe_malloc(key_size);
    header.shares      = safe_malloc(sharecount * sizeof(share_data_t));

    pbkdf2_itertime(hash_idx, key_size, 100);
    for (i = 0;i < sharecount; i++) {
      snprintf( prompt, 64, "Enter Password  [%d/%d]: ", i + 1, sharecount);
      snprintf(vprompt, 64, "Verify Password [%d/%d]: ", i + 1, sharecount);
      pass_ret = get_pass(pass, 128, prompt, vprompt, "Passwords did not match, please try again.", 10);
      if (pass_ret < 0) {
        fprintf(stderr, "Password entry failed.\n");
        exit(EXIT_FAILURE);
      } else if (pass_ret < 1) {
        fprintf(stderr, "Password must be at least one character(s)\n");
        i--; /* Retry this keyslot */
      } else {
        assert(pass_ret == (int)strlen(pass));
        share_data_t *share = &(header.shares[i]);
        share->iter = MAX(1024, base_iter ^ (random() & 0x01ff));
        share->key  = safe_malloc(key_size);
        fill_prng(share->salt, salt_size);
        pbkdf2(pass, pass_ret, share->salt, salt_size, share->iter, hash_idx, share->key, &key_size);
        memset(pass, 0, sizeof(pass));
      }
    }
    ret = tc_gfsplit(&header);

    /* open output file */
    if (out_file != NULL) {
      if ((out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
        fprintf(stderr, "%s: Failed to open '%s' for writing: ", progname, out_file);
        perror("");
        exit(EXIT_FAILURE);
      }
    } else {
      out_fd = fileno(stdout);
    }
    write_header(&header, out_fd);
    /* encrypt data */
    /* This is a do-while loop so that a final zero-length data block will *
     * written as an authenticated EoF marker                              */
    ssize_t len;
    unsigned char *IV = NULL;
    assert(header.master_key != NULL);
    do {
      if ((len = read(in_fd, buf, BUFFER_SIZE)) < 0) {
        perror("Input file read error: ");
        exit(EXIT_FAILURE);
      }
      unsigned char blklen[4];
      unsigned char blkmac[32];

      encrypt_block(buf, buf, len,
                   header.master_key, header.key_size,
                   blkmac, header.hmac_size, IV);
      uint32_t ulen = len;
      STORE32H(ulen, blklen);
      write(out_fd, blklen,   4);
      write(out_fd, buf, len);
      write(out_fd, blkmac, header.hmac_size);
    } while (len > 0);
    free_header(&header);
    return ret;
  }

  return -1;
}

/* vim: set ts=2 sw=2 et ai si: */
