CFLAGS += -g -O0 -std=gnu99 -fPIC -Wall -Wextra -Werror -Wno-unused-parameter
CPPFLAGS += -I../bignum/out -I../shitlisp/out

all: testaes testsha2 cifra.so

SOURCES = aes.o sha256.o sha512.o chash.o hmac.o pbkdf2.o modes.o eax.o blockwise.o cmac.o

testaes: $(SOURCES) testaes.o
testsha2: $(SOURCES) testsha2.o
testsc: testsc.o

cifra.so: $(SOURCES) sl-cifra.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -shared

clean:
	rm -f *.o *.pyc testaes testsha2 cifra.so

test: testaes testsha2 cifra.so $(wildcard test-*.sl)
	./testaes
	./testsha2
	../shitlisp/out/shitlisp --mod=./cifra.so $(wildcard test-*.sl)
