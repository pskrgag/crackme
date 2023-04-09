#include "syscalls.h"

extern char payload[];


int main(void)
{
	write(1, "hello", 5);
	exit(10);
}
