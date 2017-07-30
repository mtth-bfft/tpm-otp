BINARIES=main
CFLAGS=-Wall -Wextra -Werror -pedantic -std=c11 -Iinclude/
LDFLAGS=-O1
DEBUG ?= 0
ifneq ($(DEBUG), 0)
	CFLAGS+=-O0 -ggdb -DDEBUG
endif

default: $(BINARIES)

%: src/%.o src/crypto.o
	$(CC) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c include/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(BINARIES) src/*.o
