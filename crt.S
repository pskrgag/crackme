.global _start
.section .boot.text, "ax"
_start:
//	movq	%rax, stack
//	mov	%rcx, 8192
//	add	%rax, %rcx
//	mov	%rsp, %rax
	jmp	main

.align 16
.global stack
stack:
	.fill	2 * 4096, 1, 0xa

