# Spinning Top

This challenge converts a flag to a binary string, encrypts it with AES in CBC mode, and asks you to figure out what the flag is.

The encrypted flag looks something like:
```
0b10101110101011000101...
```

CBC chains blocks together when encrypting, xoring each block by an initial value, the IV. If the IV is not random, each encryption of certian text will be the same.

Since each block is encrypted one at a time, starting at the beginning, we will be able to know if we have found the first block because the first 16 bytes of the xor will be 0.
```python
print(str(binascii.hexlify(xor_guess_flag(ct_guess, ct)), 'utf8'))
```

Once we know the first block, we can repeat the same process to find the second block.

If we can guess all the possibilities for each block, we can solve the challenge. Since the flag is encoded as binary, there is a brute forceable number of possibilities. The thing to be careful of is that the first block of the flag is automatically padded with spaces.

An implementation of this solve, brute forcing one CBC block at a time, is available in `solve.py`.
