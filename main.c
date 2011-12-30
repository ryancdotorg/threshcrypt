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

/* globals so that signal/atexit handlers can get at them */
static header_data_t *header;
static secmem_t      *secmem;

static void cleanup(void) {
  /* fprintf(stderr, "Freeing header\n"); */
  free_header(header);
}

static void sig_handle(int sig) {
  if (sig == SIGINT) { load_term(&orig_term_set); fprintf(stderr, "\n"); }
  fprintf(stderr, "%s caught, exiting\n", strsignal(sig));
  exit(EXIT_FAILURE);
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
  float spi = 0; /* seconds per iter */

  /* loop until we find a value for iter that takes at least 0.10 seconds */
  while (duration < 0.10) { /* minimum time */
    gettimeofday(&time1, NULL);
    pbkdf2(pass, strlen(pass), salt, strlen(salt), iter, hash_idx, buf, &size);
    gettimeofday(&time2, NULL);
    duration = (time2.tv_sec - time1.tv_sec) + (float)(time2.tv_usec - time1.tv_usec) / 1000000;
    spi = 1000 * duration / iter; /* calculate seconds per iter */
    /*fprintf(stderr, "PBKDF2: %6.3fs,%7diter,%10.3e\n", duration, iter, spi);*/
    /* set iter to a value expected to take around 0.12 seconds*/
    iter = 0.12 * 1000 / spi;
  }
  safe_free(buf);
  if (msec > INT_MAX * spi) { /* return INT_MAX instead of undefined behaviour */
    fprintf(stderr, "PBKDF2: ??.???s,%7diter\n", INT_MAX);
    return INT_MAX;
  }
  fprintf(stderr, "PBKDF2: %6.3fs,%7diter\n", (float) msec / 1000, (int)(msec / spi));
  return (int)(msec / spi);
}

void usage(FILE* stream) {
  fprintf(stream, "\
Usage: threshcrypt [options] infile [outfile]\n\
\n\
Where options are:\n\
\n\
  -h    show this screen (all other options ignored)\n\
  -V    print version infomation (all other options ignored)\n\
\n\
  -d    do decryption (default if no options specified)\n\
  -e    do encryption (default if any of the following options are set)\n\
\n\
  -n    total number of passwords to enter\n\
  -t    minimum number of passwords that will be required to decrypt\n\
\n\
  -m    time in milliseconds to iterate for pbkdf2\n\
  -i    number of iterations to use for pbkdf2\n\
\n\
The shares option defaults to %d.\n\
The threshold option defaults to %d.\n\
", DEFAULT_SHARECOUNT, DEFAULT_THRESHOLD );
}

#define OPTSTRING "b:i:t:n:m:hVed"
int main(int argc, char **argv) {
  unsigned int sharecount = DEFAULT_SHARECOUNT;
  unsigned int threshold  = DEFAULT_THRESHOLD;
  unsigned int key_bits   = DEFAULT_KEY_BITS;
           int mode       = MODE_UNKNOWN;
           int iter       = DEFAULT_ITERATIONS;
           int iter_ms    = 0;

  unsigned char buf[BUFFER_SIZE];

  char *in_file, *out_file;
  int in_fd, out_fd;

  char *endptr;
  int optnr;
  
  unsigned int i;
  int ret, err;
  ret = err = 0;

  /* malloc the header and secmem structs */
  header = safe_malloc(sizeof(header_data_t));
  secmem = safe_malloc(sizeof(secmem_t));
  
  /* make sure key material is wiped on exit */ 
  atexit(cleanup);

  /* set up signal handlers */
  save_term(&orig_term_set);
  /* catch some signals we can */
  signal(SIGINT, sig_handle);
  signal(SIGHUP, sig_handle);
  signal(SIGUSR1, sig_handle);
  signal(SIGUSR2, sig_handle);
  signal(SIGTERM, sig_handle);
  signal(SIGPIPE, sig_handle);
  signal(SIGABRT, sig_handle);

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
    case 'V':
      fprintf(stdout, "\
threshcrypt %s, Copyright 2012 Ryan Castellucci <code@ryanc.org>\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
", THRCR_VERSION_STR);
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
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -i, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      iter = strtoul( optarg, &endptr, 10 );
      if (*endptr != 0 || *optarg == 0 || 
          iter < 1024 || iter > INT_MAX ) {
          fprintf(stderr, "%s: Invalid argument to option -i (%d)\n", progname, iter);
          usage(stderr);
          return 1;
      }
      break;
    case 'm':
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -i, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      iter_ms = strtoul(optarg, &endptr, 10);
      mode = MODE_ENCRYPT;
      if (*endptr != 0 || *optarg == 0 || 
          iter_ms < 1 || iter_ms > MAX_ITER_MS ) {
          fprintf(stderr, "%s: Invalid argument to option -m (%d)\n", progname, iter_ms);
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
    case 'n':
      sharecount = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -n, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if( *endptr != 0 || *optarg == 0 || 
          sharecount < 1 || sharecount > 255 ) {
        fprintf(stderr, "%s: Invalid argument to option -n (%d)\n", progname, sharecount );
        usage(stderr);
        return 1;
      }
      break;
    case 't':
      threshold = strtoul( optarg, &endptr, 10 );
      if (mode == MODE_DECRYPT) {
        fprintf(stderr, "%s: Conflicting mode option -t, mode set to decrypt by previous option\n", progname);
        return 1;
      }
      mode = MODE_ENCRYPT;
      if( *endptr != 0 || *optarg == 0 || threshold < 1) {
        fprintf(stderr, "%s: Invalid argument to option -t (%d)\n", progname, threshold );
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

  size_t key_size = key_bits / 8;
  size_t salt_size = SALT_SIZE;
  size_t hmac_size = HMAC_SIZE;
  size_t share_size = key_size + 1;

  /* secmem_init(secmem); */
  header->secmem = secmem;

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
      return THRCR_ERROR;
    }
    if ((err = parse_header(buf, header)) != THRCR_OK) {
      switch(err) {
        case THRCR_NOMAGIC:
          fprintf(stderr, "%s: Error reading header of '%s': no magic\n", progname, in_file);
          return THRCR_NOMAGIC;
          break;
        case THRCR_BADDATA:
          fprintf(stderr, "%s: Error reading header of '%s': bad data\n", progname, in_file);
          return THRCR_BADDATA;
          break;
      }
      /* shouldn't be reached */
      fprintf(stderr, "%s: Unexpected return for parse_header: %d\n", progname, err);
      return THRCR_ERROR;
    }

    /* unlock shares */
    int unlocked = 0;
    while (unlocked < header->thresh) {
      fprintf(stderr, "More passwords are required to meet decryption threshold.\n");
      snprintf(prompt, 64, "Enter any remaining share password [%d/%d]: ", unlocked, header->thresh);
      pass_ret = get_pass(pass, 128, prompt, NULL, NULL, 0);
      if (pass_ret < 0) {
        fprintf(stderr, "Password entry failed.\n");
        return THRCR_ERROR;
      } else if (pass_ret < 1) {
        fprintf(stderr, "Password must be at least one character(s)\n");
      } else {
        assert(pass_ret == (int)strlen(pass));

        int unlock_ret;
        if ((unlock_ret = unlock_shares(pass, pass_ret, header))){
          unlocked += unlock_ret;
        }
        MEMZERO(pass, sizeof(pass));
      }
    }
    fprintf(stderr, "Decrypting data...\n");
    /* Recover master key */
    tc_gfcombine(header);

    assert(header->master_key != NULL);

    /* verify master key */
    size_t hmac_size = header->hmac_size;
    if ((err = pbkdf2_vrfy(header->master_key, header->key_size, header->master_salt, SALT_SIZE,
                           SUBKEY_ITER, hash_idx, header->master_hmac, &hmac_size)) != CRYPT_OK) {
      fprintf(stderr, "Master key verification failed!\n");
      exit(EXIT_FAILURE);
    }
    /* share ptxt/keys no longer needed */
    wipe_shares(header);

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
    uint32_t dlen;
    unsigned char *IV = NULL;
    do {
      unsigned char blkmac[32];

      len = read(in_fd, buf, 4);
      if (len < 4) {
        fprintf(stderr, "%s: Error: short read of blocklen in '%s'\n", progname, in_file);
        ret = THRCR_READERR;
        break;
      }
      LOAD32H(dlen, buf);
      if (dlen > sizeof(buf)) {
        fprintf(stderr, "%s: Error: blocklen larger than BUFFER_SIZE: '%s'\n", progname, in_file);
        ret = THRCR_BADDATA;
        break;
      }
      if ((len = read(in_fd, buf, dlen)) < (ssize_t)dlen) {
        fprintf(stderr, "%s: Error: short read of blockdat in '%s'\n", progname, in_file);
        ret = THRCR_READERR;
        break;
      }
      if ((len = read(in_fd, blkmac, header->hmac_size)) < header->hmac_size) {
        fprintf(stderr, "%s: Error: short read of blockmac in '%s'\n", progname, in_file);
        ret = THRCR_READERR;
        break;
      }
      if ((err = decrypt_block(buf, buf, dlen,
                               header->master_key, header->key_size,
                               blkmac, header->hmac_size, IV)) != THRCR_OK) {
        fprintf(stderr, "Error: Failed to decrypt block\n");
        ret = THRCR_DECERR;
        break;
      }
      if ((err = write(out_fd, buf, dlen) < (ssize_t)dlen)) {
        if (err == -1) {
          perror("Error writing output");
        } else {
          fprintf(stderr, "Error: Short write to output\n");
        }
        ret = THRCR_WRITEERR;
        break;
      }
    } while (dlen > 0);
    close(in_fd);
    close(out_fd);
    MEMZERO(buf, BUFFER_SIZE);
    return ret;
  } /* end MODE_DECRYPT */

  if (mode == MODE_ENCRYPT) {
    unsigned char magic[THRCR_MAGIC_LEN]     = THRCR_MAGIC;
    unsigned char version[THRCR_VERSION_LEN] = THRCR_VERSION;

    memcpy(header->magic,   magic,   THRCR_MAGIC_LEN);
    memcpy(header->version, version, THRCR_VERSION_LEN);
    header->cipher      = 1; /* Hardcoded for now */
    header->hash        = 1; /* Hardcoded for now */
    header->kdf         = 1; /* Hardcoded for now */
    header->nshares     = sharecount;
    header->thresh      = threshold;
    header->key_size    = key_size;
    header->hmac_size   = hmac_size;
    header->share_size  = share_size;
    header->master_iter = SUBKEY_ITER;
    header->master_hmac = safe_malloc(hmac_size);
    header->master_key  = secmem_alloc(header->secmem, key_size);
    header->shares      = safe_malloc(sharecount * sizeof(share_data_t));

    if (iter_ms) {
      iter = pbkdf2_itertime(hash_idx, key_size, iter_ms);
    }
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
        share_data_t *share = &(header->shares[i]);
        share->iter = MAX(1024, iter ^ (random() & 0x01ff));
        share->key  = secmem_alloc(header->secmem, key_size);
        fill_prng(share->salt, salt_size);
        pbkdf2(pass, pass_ret, share->salt, salt_size, share->iter, hash_idx, share->key, &key_size);
        MEMZERO(pass, sizeof(pass));
      }
    }
    ret = tc_gfsplit(header);
    /* master_key generated and set, shares should be clean */

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
    write_header(header, out_fd);
    /* encrypt data */
    ssize_t len;
    unsigned char *IV = NULL;
    assert(header->master_key != NULL);
    do {
      if ((len = read(in_fd, buf, BUFFER_SIZE)) < 0) {
        perror("Input file read error");
        exit(EXIT_FAILURE);
      }
      unsigned char blklen[4];
      unsigned char blkmac[32];

      if ((err = encrypt_block(buf, buf, len,
                               header->master_key, header->key_size,
                               blkmac, header->hmac_size, IV)) != THRCR_OK) {
        fprintf(stderr, "Error: Failed to encrypt block\n");
        MEMZERO(buf, BUFFER_SIZE);
        exit(EXIT_FAILURE);
      }
      uint32_t ulen = len;
      STORE32H(ulen, blklen);
      if ((err = write(out_fd, blklen, 4)                 < 4) ||
          (err = write(out_fd, buf, len)                  < (ssize_t)len) ||
          (err = write(out_fd, blkmac, header->hmac_size) < (ssize_t)(header->hmac_size))) {
        if (err == -1) {
          perror("Error writing output");
        } else {
          fprintf(stderr, "Error: Short write to output\n");
        }
        ret = THRCR_WRITEERR;
        break;
      }
      /* The final block is zero len and acts as an authenticate EoF marker */
    } while (len > 0);
    close(in_fd);
    close(out_fd);
    MEMZERO(buf, BUFFER_SIZE);
    return ret;
  }

  close(in_fd);
  return THRCR_ERROR;
}

/* vim: set ts=2 sw=2 et ai si: */
