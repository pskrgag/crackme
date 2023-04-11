#include "paylaod.h"
#include "./tiny-AES-c/aes.h"
#include "syscalls.h"
#include "elf.h"
#include "lib.h"

extern char payload[];

#define dbg(str)	write(1, str, sizeof(str));
#define STR(x)		_STR(x)
#define _STR(x)		#x

#define SANITY(x)	do { if (__builtin_expect(!!(x), 0)) { dbg("Error at " STR(__FILE__) ":" STR(__LINE__) "\n") exit(10); } } while (0)

#define PAGE_DOWN(x)	(UL(x) & ~4095)


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

		__builtin_memcpy(res, payload + cur->p_offset, cur->p_filesz);

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
void* elf_base_addr(void *rsp) {
    void *base_addr = NULL;
    unsigned long argc = *(unsigned long*)rsp;
    char **envp = rsp + (argc+2)*sizeof(unsigned long); // Указатель на первую
                                                        // переменную среды
    while(*envp++); // Проходимся по всем указателям на переменные среды
    Elf64_auxv_t *aux = (Elf64_auxv_t*)envp; // Первая запись вспомогательного
                                             // вектора

    for(; aux->a_type != AT_NULL; aux++) {
        // Если текущая запись содержит адрес заголовков программы
        if(aux->a_type == AT_PHDR) {
            // Вычитаем размер ELF заголовка, так как обычно заголовки
            // программы располагаются срузу после него
            base_addr = (void*)(aux->a_un.a_val - sizeof(Elf64_Ehdr));
            break;
        }
    }

    return base_addr;
}

static void __attribute__((noinline)) jump_to_binary(const void *bin, const void *sp)
{
	unsigned long *stack = sp;
	const Elf64_Ehdr *hdr = bin;

	//*stack = 0xaaaaaaaaaaa;

	asm volatile ("mov	%%rsp, %1\n"
		      "xor	%%r13, %%r13\n"
		      "jmp	*%0"
		      ::"b"(hdr->e_entry), "r"(sp));
}

int main(char *sp)
{
	struct result_binary *bin = (void *) &payload;
	struct AES_ctx ctx;

	dbg("[*] Loader starts\n");

	AES_init_ctx_iv(&ctx, (void *) &bin->key, (void *) &bin->iv);
	AES_CTR_xcrypt_buffer(&ctx, (void *) bin->payload, bin->payload_size);

	dbg("[*] Decrypted payload\n");

	check_payload((void *) bin->payload);
	map_elf((void *) bin->payload);

	jump_to_binary((void *) bin->payload, sp);

	exit(0);
}
