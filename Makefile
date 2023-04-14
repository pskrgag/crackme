CFLAGS := -g3 -O2 -I./include/
CC := gcc

.PHONY: loader payload aes

all: aes loader main.c payload
	$(CC) main.c -o packer $(CFLAGS) ./tiny-AES-c/build/libtiny-aes.a

aes:
	cd ./tiny-AES-c; mkdir build || true; cd build; cmake -DCMAKE_C_FLAGS='-fno-stack-protector -fPIE' ..; make -j

loader:
	$(MAKE) -C ldr/

payload: payload.c
	$(CC) -static -O2 payload.c -o payload
