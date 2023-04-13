all: loader.c loader.ld crt.S
	$(CC) -Wall -Wextra -O2 -fno-stack-protector -ffreestanding -nostdlib -nostartfiles -nodefaultlibs -nolibc -T loader.ld -fPIE -I../include/ -I../ crt.S loader.c -o ../loader.elf ../tiny-AES-c/build/libtiny-aes.a
	objcopy --only-section='.text*' -O binary ../loader.elf ../loader
