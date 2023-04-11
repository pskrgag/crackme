.global _start
.section .boot.text, "ax"
_start:
	mov	%rsp, %rax
	jmp	main
