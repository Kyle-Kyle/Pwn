from pwn import *
context.arch = 'amd64'

r = remote('rev.chal.csaw.io', 9004)
#r = process(['python3', 'part-3-server.py'])

payload = asm("""
	call .get_ip
	mov rdi, 0x00b8000

	mov rcx, 0x30

	.print_one_char:
	mov bl, byte ptr [rax]
	mov byte ptr [rdi], bl
	inc rdi
	mov byte ptr [rdi], 0x1f
	inc rdi
	inc rax
	loop .print_one_char

	hlt

	.get_ip:
	pop rax
	push rax
	add rax, 40
	ret
""")
print len(payload)
r.sendlineafter('for four nops:\n', payload.encode('hex'))

r.interactive()
