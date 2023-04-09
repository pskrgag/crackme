CFLAGS := -g3 -O2
CC := gcc

.PHONY: loader

all: loader main.c
	$(CC) main.c -o test ./tiny-AES-c/build/libtiny-aes.a

loader: loader.c crt.S loader.ld
	$(CC) -ffreestanding -nostdlib -nostartfiles -nodefaultlibs -nolibc -T loader.ld -fPIE -Xlinker --no-dynamic-linker $(CFLAGS) crt.S loader.c -o loader.elf
	rm tmp
	objcopy -O binary loader.elf loader
