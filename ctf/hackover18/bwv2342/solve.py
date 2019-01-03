#hackover18{M0V_70_7h4_w0h173mp3r13r73_Kl4v13r}
import string
from pwn import *

r = process('./bwv2342')
#r = remote('bwv2342.ctf.hackover.de', 1337)
context.log_level = 'DEBUG'
charset = string.ascii_letters+string.digits+'"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
#flag = 'hackover18{M0V_70_7h'
flag = ''

for i in range(60):
	res = {}
	for c in charset:
		r.sendlineafter('Please enter your guess:\n', flag+c)
		value = r.recvline()
		if value in res:
			res[value].append(c)
		else:
			res[value] = [c]
	#print res
	l = 0x100
	min_key = None
	for key in res.keys():
		if len(res[key]) < l:
			l = len(res[key])
			min_key = key
		elif len(res[key]) == 1:
			print len(res[key])
	
	assert l == 1
	flag += res[min_key][0]
	print flag
	print res

r.interactive()

