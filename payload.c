#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Put it here to make madvise(DONT_DUMP) work */
static long long __attribute__((used)) hash = 0; /* prevent compiler to optimize out */

long long compute_hash(const char *s)
{
	const int p = 31;
	const int m = 1e9 + 9;
	long long p_pow = 1;
	unsigned i;

	for (i = 0; i < strlen(s); ++i) {
		hash = (hash + (s[i] - 'a' + 1) * p_pow) % m;
		p_pow = (p_pow * p) % m;
	}

	return hash;
}

int main(void)
{
	char data[500];
	long long hash_user;

	printf("Enter txt: ");
	fgets(data, sizeof(data), stdin);

	hash = compute_hash(data);

	printf("Provide secret: ");
	fgets(data, sizeof(data), stdin);

	hash_user = atoll(data);

	if (hash == hash_user)
		printf("\n[POSIX] unifying unix? more like formalizing historical design mistakes made by major vendors...\n\n— ttyv0\n");
	else
		printf("Bad guess, try again\n");

	fflush(stdout);

	/* %%fs register is used in _fini stuff in libc. don't go there, since i do not set it */
	_Exit(0);
}
