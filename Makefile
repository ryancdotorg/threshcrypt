HEADERS = main.h ui.h shares.h cyrpt.h util.h file.h common.h
OBJECTS = main.o ui.o shares.o crypt.o util.o file.o
LIBS = -lgfshare -ltomcrypt
COMPILE = gcc $(CFLAGS) -g -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign

.c.o:
	$(COMPILE) -c $< -o $@

threshcrypt: $(OBJECTS)
	$(COMPILE) $(OBJECTS) $(LIBS) -o threshcrypt

threshcrypt_static: $(OBJECTS)
	$(COMPILE) -static $(OBJECTS) $(LIBS) -o threshcrypt_static
	strip threshcrypt_static
	@which upx && upx --best threshcrypt_static || true

threshcrypt_embed: $(OBJECTS)
	$(COMPILE) $(OBJECTS) -Wl,-Bstatic $(LIBS) -Wl,-Bdynamic -o threshcrypt_embed
	strip threshcrypt_embed

static: threshcrypt_static

embed: threshcrypt_embed

extra: threshcrypt threshcrypt_embed threshcrypt_static

all: threshcrypt

clean:
	rm -f threshcrypt threshcrypt_* *.o
