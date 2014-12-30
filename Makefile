CFLAGS += -g -O0 -std=gnu99 -fPIC -Wall -Wextra -Werror -Wno-unused-parameter
CPPFLAGS += -I../bignum/out -I../shitlisp/out

TARGETS = testaes testsha2 testsalsa20 cifra.so
all: $(TARGETS)

SOURCES = aes.o sha256.o sha512.o chash.o hmac.o pbkdf2.o modes.o eax.o \
	  blockwise.o cmac.o salsa20.o chacha20.o

testaes: $(SOURCES) testaes.o
testsha2: $(SOURCES) testsha2.o
testsalsa20: $(SOURCES) testsalsa20.o
testsc: testsc.o

cifra.so: $(SOURCES) sl-cifra.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -shared

clean:
	rm -f *.o *.pyc $(TARGETS)

test: testaes testsha2 testsalsa20 cifra.so $(wildcard test-*.sl)
	./testaes
	./testsha2
	./testsalsa20
	../shitlisp/out/shitlisp --mod=./cifra.so $(wildcard test-*.sl)
