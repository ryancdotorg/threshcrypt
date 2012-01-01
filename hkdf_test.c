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

#include <tomcrypt.h>

#include "hkdf.h"
#include "hkdf_test.h"

void print_hex(const unsigned char * ptr, size_t len, size_t width) {
  size_t i;
  if (len > 0)
    printf(" 0x");
  for (i = 0; i < len; i++) {
    if (i > 0 && i % width == 0) {
      printf(" \n         ");
    }
    printf("%02x", ptr[i]);
  }
  printf(" (%d octets)\n", (int)len);
}

unsigned char * hexstrstr(const char * hexstr) {
  int len = strlen(hexstr);
  assert(len % 2 == 0);
  assert(len > 1);

  len >>= 1; /* bit shift to divide by two */

  unsigned char *out = XMALLOC(len);
  if (out == NULL)
    abort();

  while (len-- > 0)
    sscanf(hexstr + len * 2, "%02hhx", out + len);
    
  return out;
}

int test_hkdf(const char * hash,
              const unsigned char * IKM,  size_t IKM_len,
              const unsigned char * salt, size_t salt_len,
              const unsigned char * info, size_t info_len,
              const unsigned char * PRK,  size_t PRK_len,
              const unsigned char * OMK,  size_t OMK_len) {
  int hash_idx = find_hash(hash);
  unsigned long hashsize = hash_descriptor[hash_idx].hashsize;

  assert(PRK_len == hashsize);

  int ret = 0;

  unsigned char *test_PRK = XMALLOC(PRK_len);
  if (test_PRK == NULL)
    abort();
  unsigned char *test_OMK = XMALLOC(OMK_len);
  if (test_OMK == NULL)
    abort();

  XMEMSET(test_PRK, 0x55, PRK_len);
  XMEMSET(test_OMK, 0x55, OMK_len);

  printf("Hash = %s\n", hash);
  printf("IKM  =");
  print_hex(IKM,  IKM_len,  IKM_len  >= 32 ? 16 : 32);
  printf("salt =");
  if (salt != NULL) {
    print_hex(salt, salt_len, salt_len >= 32 ? 16 : 32);
  } else {
    printf(" not provided (defaults to HashLen zero octets)\n");
  }
  printf("info =");
  print_hex(info, info_len, info_len >= 32 ? 16 : 32);

  printf("L    = %d\n\n", (int)OMK_len);
  
  hkdf_extract(hash_idx, salt, salt_len, IKM, IKM_len, test_PRK, &hashsize);
  printf("PRK  =");
  print_hex(test_PRK, hashsize, hashsize >= 32 ? 16 : 32);
  if (XMEMCMP(PRK, test_PRK, PRK_len) != 0) {
    ret = -1;
    printf("PRK FAILED\n");
    goto test_abort;
  }

  hkdf_expand(hash_idx, test_PRK, hashsize, info, info_len, test_OMK, OMK_len);
  printf("OMK  =");
  print_hex(test_OMK, OMK_len, OMK_len >= 32 ? 16 : 32);
  if (XMEMCMP(OMK, test_OMK, OMK_len) != 0) {
    ret = -1;
    printf("OMK FAILED\n");
    goto test_abort;
  }

  test_abort:
  XFREE(test_PRK);
  XFREE(test_OMK);
  return ret;
}
int main() {

  /* register tomcrypt hash algorithms */
  if (register_hash(&sha1_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-1\n");
    exit(EXIT_FAILURE);
  }
  
  if (register_hash(&sha256_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-256\n");
    exit(EXIT_FAILURE);
  }

  if (register_hash(&sha384_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-384\n");
    exit(EXIT_FAILURE);
  }
  
  if (register_hash(&sha512_desc) == -1) {
    fprintf(stderr, "Failed to register SHA-512\n");
    exit(EXIT_FAILURE);
  }
  
  if (register_hash(&whirlpool_desc) == -1) {
    fprintf(stderr, "Failed to register WHIRLPOOL\n");
    exit(EXIT_FAILURE);
  }
  /* end tomcrypt algorithm registration */

  int ret = 0;

  printf("Test Case 1\n");
  if (test_hkdf("sha256",
          hexstrstr("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                    "0b0b0b0b0b0b"), 22,
          hexstrstr("000102030405060708090a0b0c"), 13,
          hexstrstr("f0f1f2f3f4f5f6f7f8f9"), 10,
          hexstrstr("077709362c2e32df0ddc3f0dc47bba63"
                    "90b6c73bb50f9c3122ec844ad7c2b3e5"), 32,
          hexstrstr("3cb25f25faacd57a90434f64d0362f2a"
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865"), 42) == 0) {
    printf("Test Case 1: OKAY\n");
  } else {
    printf("Test Case 1: FAIL\n");
    ret = 1;
  }

  printf("\n");

  printf("Test Case 2\n");
  if (test_hkdf("sha256",
          hexstrstr("000102030405060708090a0b0c0d0e0f"
                    "101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f"
                    "303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f"), 80,
          hexstrstr("606162636465666768696a6b6c6d6e6f"
                    "707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f"
                    "909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), 80,
          hexstrstr("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), 80,
          hexstrstr("06a6b88c5853361a06104c9ceb35b45c"
                    "ef760014904671014a193f40c15fc244"), 32,
          hexstrstr("b11e398dc80327a1c8e7f78c596a4934"
                    "4f012eda2d4efad8a050cc4c19afa97c"
                    "59045a99cac7827271cb41c65e590e09"
                    "da3275600c2f09b8367793a9aca3db71"
                    "cc30c58179ec3e87c14c01d5c1f3434f"
                    "1d87"), 82) == 0) {
    printf("Test Case 2: OKAY\n");
  } else {
    printf("Test Case 2: FAIL\n");
    ret = 1;
  }

  printf("\n");

  printf("Test Case 3\n");
  if (test_hkdf("sha256",
          hexstrstr("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                    "0b0b0b0b0b0b"), 22,
                    "", 0,
                    "", 0,
          hexstrstr("19ef24a32c717b167f33a91d6f648bdf"
                    "96596776afdb6377ac434c1c293ccb04"), 32,
          hexstrstr("8da4e775a563c18f715f802a063c5a31"
                    "b8a11f5c5ee1879ec3454e5f3c738d2d"
                    "9d201395faa4b61a96c8"), 42) == 0) {
    printf("Test Case 3: OKAY\n");
  } else {
    printf("Test Case 3: FAIL\n");
    ret = 1;
  }

  printf("\n");
  
  printf("Test Case 4\n");
  if (test_hkdf("sha1",
          hexstrstr("0b0b0b0b0b0b0b0b0b0b0b"), 11,
          hexstrstr("000102030405060708090a0b0c"), 13,
          hexstrstr("f0f1f2f3f4f5f6f7f8f9"), 10,
          hexstrstr("9b6c18c432a7bf8f0e71c8eb88f4b30b"
                    "aa2ba243"), 20,
          hexstrstr("085a01ea1b10f36933068b56efa5ad81"
                    "a4f14b822f5b091568a9cdd4f155fda2"
                    "c22e422478d305f3f896"), 42) == 0) {
    printf("Test Case 4: OKAY\n");
  } else {
    printf("Test Case 4: FAIL\n");
    ret = 1;
  }

  printf("\n");

  printf("Test Case 5\n");
  if (test_hkdf("sha1",
          hexstrstr("000102030405060708090a0b0c0d0e0f"
                    "101112131415161718191a1b1c1d1e1f"
                    "202122232425262728292a2b2c2d2e2f"
                    "303132333435363738393a3b3c3d3e3f"
                    "404142434445464748494a4b4c4d4e4f"), 80,
          hexstrstr("606162636465666768696a6b6c6d6e6f"
                    "707172737475767778797a7b7c7d7e7f"
                    "808182838485868788898a8b8c8d8e8f"
                    "909192939495969798999a9b9c9d9e9f"
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), 80,
          hexstrstr("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), 80,
          hexstrstr("8adae09a2a307059478d309b26c4115a"
                    "224cfaf6"), 20,
          hexstrstr("0bd770a74d1160f7c9f12cd5912a06eb"
                    "ff6adcae899d92191fe4305673ba2ffe"
                    "8fa3f1a4e5ad79f3f334b3b202b2173c"
                    "486ea37ce3d397ed034c7f9dfeb15c5e"
                    "927336d0441f4c4300e2cff0d0900b52"
                    "d3b4"), 82) == 0) {
    printf("Test Case 5: OKAY\n");
  } else {
    printf("Test Case 5: FAIL\n");
    ret = 1;
  }

  printf("\n");
  
  printf("Test Case 6\n");
  if (test_hkdf("sha1",
          hexstrstr("0b0b0b0b0b0b0b0b0b0b0b0b0b"
                    "0b0b0b0b0b0b0b0b0b"), 22,
                    "", 0,
                    "", 0,
          hexstrstr("da8c8a73c7fa77288ec6f5e7c297786a"
                    "a0d32d01"), 20,
          hexstrstr("0ac1af7002b3d761d1e55298da9d0506"
                    "b9ae52057220a306e07b6b87e8df21d0"
                    "ea00033de03984d34918"), 42) == 0) {
    printf("Test Case 6: OKAY\n");
  } else {
    printf("Test Case 6: FAIL\n");
    ret = 1;
  }

  printf("\n");
  
  printf("Test Case 7\n");
  if (test_hkdf("sha1",
          hexstrstr("0c0c0c0c0c0c0c0c0c0c0c0c0c"
                    "0c0c0c0c0c0c0c0c0c"), 22,
                    NULL, 0,
                    "", 0,
          hexstrstr("2adccada18779e7c2077ad2eb19d3f3e"
                    "731385dd"), 20,
          hexstrstr("2c91117204d745f3500d636a62f64f0a"
                    "b3bae548aa53d423b0d1f27ebba6f5e5"
                    "673a081d70cce7acfc48"), 42) == 0) {
    printf("Test Case 7: OKAY\n");
  } else {
    printf("Test Case 7: FAIL\n");
    ret = 1;
  }

  return ret;
}

/* vim: set ts=2 sw=2 et ai si: */
