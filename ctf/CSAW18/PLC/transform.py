from pwn import *

content = open('text_segment').read()
f = open('bin', 'wb')
for line in content.splitlines():
	_, _, addr1, addr2 = line.split('0x')
#	print [addr1.decode('hex')], [addr2.decode('hex')]
	addr1 = int('0x'+addr1, 16)
	addr2 = int('0x'+addr2, 16)
	f.write(p64(addr1))
	f.write(p64(addr2))
f.write('\x00'*0x1000)
