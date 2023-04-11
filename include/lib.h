#ifndef __LIB__H__
#define __LIB__H__

#include <stdint.h>
#include <stddef.h>

static inline int memcmp(const void *s, const void *d, size_t size)
{
	return __builtin_memcmp(s, d, size);
}

#endif /*  __PAYLOAD__H__ */
