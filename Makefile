HEADERS = main.h ui.h shares.h cyrpt.h util.h file.h common.h
OBJECTS = main.o ui.o shares.o crypt.o util.o file.o
LIBS = -lgfshare -ltomcrypt
COMPILE = gcc $(CFLAGS) -g -Wall -Wextra -Wno-pointer-sign

.c.o:
	$(COMPILE) -c $< -o $@

threshcrypt: $(OBJECTS)
	$(COMPILE) $(OBJECTS) $(LIBS) -o threshcrypt

threshcrypt_static: $(OBJECTS)
	$(COMPILE) -Os -static $(OBJECTS) $(LIBS) -o threshcrypt_static
	strip threshcrypt_static
	which upx && upx --ultra-brute --best threshcrypt_static

static: threshcrypt_static

all: threshcrypt

clean:
	rm -f threshcrypt threshcrypt_static *.o
