from pwn import *


f = open('solve.rb', 'r')
payload = f.read()

#r = remote('127.0.0.1', '31337')
r = remote('54.65.72.116', '31337')
#r = process('./server.rb')
r.send(payload)
print r.recvall()
#r.interactive()

