CFLAGS := -Wall -Wextra -O2 -fno-stack-protector -ffreestanding -nostdlib -fPIE
CFLAGS_INC := -I../include/ -I../


all: loader.c loader.ld crt.S
	$(CC) $(CFLAGS) -T loader.ld $(CFLAGS_INC) crt.S loader.c -o ../loader.elf ../tiny-AES-c/build/libtiny-aes.a
	objcopy --only-section='.text*' -O binary ../loader.elf ../loader
