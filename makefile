PREFIX?=/usr/local
LIBS=-lsodium
LDFLAGS=-g $(LIBS)
CFLAGS=-Wall -fPIC -fPIE -O3 -g
CC=gcc

all: tcn

libtcn.so: tcn.o
	$(CC) -shared -fpic $(CFLAGS) -o libtcn.so tcn.o $(LDFLAGS)

tcn: test.c libtcn.so
	gcc -o tcn test.c $(LDFLAGS) ./libtcn.so

install: $(PREFIX)/lib/libtcn.so $(PREFIX)/include/tcn.h

$(PREFIX)/lib/libtcn.so: libtcn.so
	cp $< $@

$(PREFIX)/include/tcn.h: tcn.h
	cp $< $@

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm *.o *.so
