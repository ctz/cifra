CFLAGS += -g -O0 -std=gnu99 -fPIC -Wall -Wextra -Werror -Wno-unused-parameter
CPPFLAGS += -I./ext -I../bignum/out -I../shitlisp/out

ifdef COVERAGE
	LDFLAGS += -coverage
	CFLAGS += -coverage
endif

TARGETS = testaes testsha2 testsalsa20 testcurve25519 
all: $(TARGETS)

SOURCES = aes.o sha256.o sha512.o chash.o hmac.o pbkdf2.o modes.o eax.o \
	  blockwise.o cmac.o salsa20.o chacha20.o curve25519.o

testaes: $(SOURCES) testaes.o
testsha2: $(SOURCES) testsha2.o
testsalsa20: $(SOURCES) testsalsa20.o
testcurve25519: $(SOURCES) testcurve25519.o

cifra.so: $(SOURCES) sl-cifra.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -shared

clean:
	rm -f *.o *.pyc $(TARGETS) *.gcov *.gcda *.gcno

test: $(TARGETS)
	./testaes
	./testsha2
	./testsalsa20
	./testcurve25519

test-sl: $(wildcard test-*.sl) cifra.so
	../shitlisp/out/shitlisp --mod=./cifra.so $(wildcard test-*.sl)

cover: test
	gcov *.c
	echo 'Lines with missing coverage:'
	grep '#####' *.gcov | grep -vE '(cutest|testutil).h.gcov'
