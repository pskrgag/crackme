.global _start
.section .boot.text, "ax"
_start:
	//mov	%rsp, %rax
	movq (%rsp), %rdi
	movq %rsp, %rsi
	addq $8, %rsi
	call main

	jmp	main
