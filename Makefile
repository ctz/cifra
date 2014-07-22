CFLAGS += -g -O0 -std=gnu99 -Wall -Wextra -Werror -Wno-unused-parameter

all: testaes testsha2

SOURCES = aes.o sha2.o

testaes: $(SOURCES) testaes.o
testsha2: $(SOURCES) testsha2.o

clean:
	rm -f *.o *.pyc testaes

test: testaes testsha2
	./testaes
	./testsha2

