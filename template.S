pre:
	call main
	db "%s", 0
main:
	pop rdi
	push rbp
	mov rbp, rsp
	sub rsp, 0
	mov rsi, gs:0x60
	ret