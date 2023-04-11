#ifndef __PAYLOAD__H__
#define __PAYLOAD__H__

#include <stdint.h>

struct result_binary {
	/* ehdr and phdr are ommited */
	uint64_t payload_size;
	uint64_t key[2];
	uint64_t iv[2];
	char payload[];
} __attribute__((packed));

#endif /*  __PAYLOAD__H__ */
