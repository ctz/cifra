CFLAGS += -g -O3 -std=gnu99 -Wall -Wextra -Werror -Wno-unused-parameter

all: testaes

SOURCES = aes.o

testaes: $(SOURCES) testaes.o

clean:
	rm -f *.o *.pyc testaes

test: testaes
	./testaes

