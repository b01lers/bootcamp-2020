# Metacortex

This challenge appears to save the address of main, read one line of input, then compare your input to the upper bits of main. Since PIE is enabled, we can't know the address of main on each program run.

There is a buffer overflow, however. The pointer to our input and the address of main is allocated on the stack during runtime. This may have been implemented in c via the `alloca` method. In both cases, a pointer is stored in memory.

If we write past our guess, we can overflow into the LSB of the pointer to the address of main. We can corrupt that pointer by writing a newline in the LSB, and cause the address compared with to be in our input.

A payload generated like this should work:
```python
payload = b'0\x00'
while len(payload) < 104:
    payload += b'\x00'

payload += b'\n'
```
