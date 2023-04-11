CFLAGS := -g3 -O2 -I./include/
CC := gcc

.PHONY: loader

all: loader main.c
	rm tmp || true
	$(CC) main.c -o test $(CFLAGS) ./tiny-AES-c/build/libtiny-aes.a

loader:
	$(MAKE) -C ldr/
