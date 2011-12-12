#!/bin/sh

gcc $CFLAGS -g -Wall -Wno-pointer-sign -c threshcrypt.c -o threshcrypt.o
gcc $CFLAGS -g -Wall -Wno-pointer-sign threshcrypt.o -lgfshare -ltomcrypt -o threshcrypt
gcc $CFLAGS -g -Wall -Wno-pointer-sign threshcrypt.o /usr/lib/libtomcrypt.a /usr/lib/libgfshare.a -o threshcrypt_embed
gcc $CFLAGS -static -g -Wall -Wno-pointer-sign threshcrypt.o -lgfshare -ltomcrypt -o threshcrypt_static
#gcc $CFLAGS -static -O2 -o threshcrypt_static -lgfshare -ltomcrypt threshcrypt.c
