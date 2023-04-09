#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <time.h>

#include "./tiny-AES-c/aes.h"

#define SANITY(x)	do { if (__builtin_expect(!!(x), 0)) error("Error at %s:%d\n", __FILE__, __LINE__); } while (0)
#define LOADER_NAME	"loader"

static size_t file_size;

static inline void __attribute((noreturn, format (printf, 1, 2))) error(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);

	exit(1);
}

static void *map_elf(int fd)
{
	void *map;

	file_size = lseek(fd, 0, SEEK_END);
	SANITY(file_size < 0);

	map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	SANITY(map == MAP_FAILED);

	return map;
}

static void check_elf(void *file)
{
	Elf64_Ehdr *hdr = file;
	const uint8_t magic[] = { 0x7f, 'E', 'L', 'F' };

	SANITY(memcmp(hdr->e_ident, magic, 4));
	SANITY(hdr->e_type != ET_EXEC);
	SANITY(hdr->e_machine != EM_X86_64);
}

static void *encrypt_elf(const char *file)
{
	size_t enc_size = (file_size + 16) + (file_size % 16);
	void *mem;
	size_t key;
	struct AES_ctx ctx;

	srand(time(NULL));

	mem = malloc(enc_size);
	SANITY(!mem);

	memcpy(mem, file, file_size);

	key = rand();

	AES_init_ctx(&ctx, &key);
	AES_CTR_xcrypt_buffer(&ctx, mem, enc_size);

	return mem;
}

static void write_file(void *loader, size_t loader_size, int fd)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdr;
	ssize_t res;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr.e_type = ET_EXEC;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_entry = 0x10000; // sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
	ehdr.e_phoff = sizeof(Elf64_Ehdr);
	ehdr.e_shoff = 0;
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_phentsize = sizeof(Elf64_Phdr);
	ehdr.e_phnum = 1;
	ehdr.e_shentsize = sizeof(Elf64_Shdr);
	ehdr.e_shnum = 0;
	ehdr.e_shstrndx = 0;

	phdr.p_type = PT_LOAD;
	phdr.p_offset = 0x1000; // sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);
	phdr.p_vaddr = 0x10000;
	phdr.p_paddr = 0;
	phdr.p_filesz = loader_size;
	phdr.p_memsz = phdr.p_filesz;
	phdr.p_flags = PF_R | PF_W | PF_X;
	phdr.p_align = 0x1000;

	res = write(fd, &ehdr, sizeof(ehdr));
	SANITY(res != sizeof(ehdr));
	res = write(fd, &phdr, sizeof(phdr));
	SANITY(res != sizeof(phdr));

	/* p_offset must be page aligned, so move cursor to page */

	lseek(fd, 4096, SEEK_SET);
	write(fd, loader, loader_size);
}

int main(int argc, char **argv)
{
	int fd = open(argv[1], O_RDONLY);
	int fd_out, fd_loader;
	void *elf, *out, *loader;
	size_t loader_size;

	SANITY(fd < 0);

	elf = map_elf(fd);
	check_elf(elf);

	fd_out = open(argv[2], O_CREAT | O_EXCL | O_RDWR, 0777);
	SANITY(fd_out < 0);

	out = encrypt_elf(elf);

	fd_loader = open(LOADER_NAME, O_RDONLY);
	SANITY(fd_loader < 0);

	loader_size = lseek(fd_loader, 0, SEEK_END);
	SANITY(loader_size < 0);

	printf("loader size %ld\n", loader_size);
	loader = mmap(NULL, loader_size, PROT_READ, MAP_PRIVATE, fd_loader, 0);
	SANITY(loader == MAP_FAILED);

	write_file(loader, loader_size, fd_out);
}
