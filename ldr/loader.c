#include "paylaod.h"
#include "./tiny-AES-c/aes.h"
#include "syscalls.h"
#include "elf.h"
#include "lib.h"
#include <sys/cdefs.h>
#include <sys/mman.h>

extern char payload[] __attribute__((aligned(8)));

#define dbg(str)	write(1, str, sizeof(str));
#define STR(x)		_STR(x)
#define _STR(x)		#x

#define SANITY(x)	do { if (__builtin_expect(!!(x), 0)) { dbg("Error at " STR(__FILE__) ":" STR(__LINE__) "\n") exit(10); } } while (0)

#define PAGE_DOWN(x)	(UL(x) & ~4095)
#define PAGE_OFFSET(x)	(UL(x) & 4095)


static void check_payload(const void *payload)
{
	const Elf64_Ehdr *hdr = payload;
	const uint8_t magic[] = { 0x7f, 'E', 'L', 'F' };

	SANITY(memcmp(hdr->e_ident, magic, 4));
	dbg("[*] Elf sanity check passed\n");
}

void memcpy(void *restrict _dest, const void *restrict _src, size_t n)
{
	char *dest = (char*)_dest;
	const char *src = (const char*)_src;
	unsigned long i;

	for(i = 0; i < n; i++)
		dest[i] = src[i];
}

void memset(void *restrict _dest, int c, size_t n)
{
	char *dest = (char*)_dest;
	unsigned long i;

	for(i = 0; i < n; i++)
		dest[i] = c;
}

static void map_elf(const void *payload)
{
	const Elf64_Ehdr *hdr = payload;
	const Elf64_Phdr *p = (payload + hdr->e_phoff);
	unsigned i;
	int pic = 0;

	SANITY(hdr->e_phoff == 0);

	for (i = 0; i < hdr->e_phnum; ++i) {
		const Elf64_Phdr *cur = p + i;

		if (cur->p_type == PT_LOAD && cur->p_vaddr == 0) {
			pic = 1;
			break;
		}
	}

	SANITY(pic);

	for (i = 0; i < hdr->e_phnum; ++i) {
		const Elf64_Phdr *cur = p + i;
		void *res;
		unsigned long flags = MAP_ANONYMOUS | MAP_PRIVATE | (!pic ? MAP_FIXED : 0);
		int ret;

		if (cur->p_type != PT_LOAD)
			continue;

		res = mmap(!pic ? (void *) PAGE_DOWN(cur->p_vaddr) : (void *) 0,
			   cur->p_memsz, PROT_WRITE, flags, -1, 0);
		SANITY((long) res < 0);

		dbg("[*] Mapped segment\n");

		__builtin_memcpy((void *) cur->p_vaddr, payload + cur->p_offset, cur->p_filesz);

		SANITY(madvise((void *) res, cur->p_memsz, MADV_DONTDUMP));

		{
			unsigned long pflags = 0;

			if (cur->p_flags & PF_R)
				pflags |= PROT_READ;
			if (cur->p_flags & PF_W)
				pflags |= PROT_WRITE;
			if (cur->p_flags & PF_X)
				pflags |= PROT_EXEC;

			ret = mprotect(res, cur->p_memsz, pflags);
		}

		SANITY(ret < 0);
	}
}

static void __attribute__((noinline, noreturn)) jump_to_binary(const void *ep, void *sp)
{
	asm volatile ("mov	%1, %%rsp\n"
		      "xor	%%rax, %%rax\n"
		      "xor	%%rcx, %%rcx\n"
		      "xor	%%rsi, %%rsi\n"
		      "xor	%%rdi, %%rdi\n"
		      "xor	%%r8, %%r8\n"
		      "xor	%%r9, %%r9\n"
		      "xor	%%r10, %%r10\n"
		      "xor	%%r11, %%r11\n"
		      "xor	%%r12, %%r12\n"
		      "xor	%%rbp, %%rbp\n"
		      "popcnt	%%eax, %%eax\n"
		      "test	%%rsp, %%rsp\n"
		      "jmp	*%0"
		      ::"b"(ep), "r"(sp));

	__builtin_unreachable();
}

int main(int argc, char **argv)
{
	(void)argc;

	void *s = argv - 1;
	struct result_binary *bin = (void *) &payload;
	struct AES_ctx ctx;
	Elf64_Ehdr *hdr = (void *) bin->payload;

	dbg("[*] Loader starts\n");

	SANITY(madvise((void *) PAGE_DOWN(bin->payload), bin->payload_size + PAGE_OFFSET(bin->payload), MADV_DONTDUMP));

	AES_init_ctx_iv(&ctx, (void *) &bin->key, (void *) &bin->iv);
	AES_CTR_xcrypt_buffer(&ctx, (void *) bin->payload, bin->payload_size);

	dbg("[*] Decrypted payload\n");

	check_payload((void *) bin->payload);
	map_elf((void *) bin->payload);


	jump_to_binary((const void *) hdr->e_entry, s);
}
