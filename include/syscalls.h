#ifndef __SYS__H__
#define __SYS__H__

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

#define MAP_PRIVATE	0x02
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_STACK	0x020000

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */

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

static inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;

	asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
		      "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");

        return ret;
}

static inline ssize_t write(int fd, const char *buf, size_t size)
{
	return syscall3(__SYS_write, fd, UL(buf), UL(size));
}

static inline void exit(int num)
{
	syscall1(__SYS_exit, num);
}

static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset)
{
	return (void *) syscall6(__SYS_mmap, UL(addr), UL(length), UL(prot), UL(flags), UL(fd), UL(offset));
}

static inline int mprotect(void *addr, size_t len, int prot)
{
	return syscall3(__SYS_mprotect, UL(addr), len, prot);
}

#endif
