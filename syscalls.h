#include <stddef.h>
#include <stdint.h>

typedef long ssize_t;

#define __SYS_read 0
#define __SYS_write 1
#define __SYS_open 2
#define __SYS_close 3
#define __SYS_fstat 5
#define __SYS_mmap 9
#define __SYS_mprotect 10
#define __SYS_munmap 11
#define __SYS_brk 12
#define __SYS_exit 60

#define UL(x)	((unsigned long) x)



static ssize_t syscall1(int num, unsigned long arg)
{
	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (num),
		      "D" (arg):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	return ret;
}

static ssize_t syscall2(int num, unsigned long arg, unsigned long arg1)
{
	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (num),
		      "D" (arg), "S" (arg1):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	return ret;
}

static ssize_t syscall3(int num, unsigned long arg, unsigned long arg1, unsigned long arg3)
{
	long ret;
	asm volatile ("syscall" : "=a" (ret) : "a" (num),
		      "D" (arg), "S" (arg1), "d"(arg3):
		      "cc", "memory", "rcx",
		      "r8", "r9", "r10", "r11" );
	return ret;
}

static inline ssize_t write(int fd, const char *buf, size_t size)
{
	return syscall3(__SYS_write, fd, UL(buf), UL(size));
}

static inline void exit(int num)
{
	return syscall1(__SYS_exit, num);
}
