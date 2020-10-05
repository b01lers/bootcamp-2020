# Strlen vs Read Writeup

This challenge is a relatively simple program that takes two inputs, and xors them together.

In order to solve the challenge, we have to find a way to modify the variable changeme, which is allocated on the heap and starts at 0xff, and is never directly modified in the program.
```c
int * changeme = malloc(sizeof(int));
*changeme = 255;
printf("Reality: %d\n", *changeme);

...

if (*changeme != 0xff) {
    system("/bin/sh");
}
```

Your first input is on the stack and has a max size of 256 bytes:
```c
char buffer[256];
int len = 256;

printf("Neo, enter your matrix: ");
len = read(0, buffer, len);
```

The second input is on the heap and has a max size equal to the length of your previous input.
```
char * buffer2 = malloc(strlen(buffer));

...

printf("Make your choice: ");
len = read(0, buffer2, len);
```

This is where the bug lies. The size of `buffer2` is `strlen(buffer)`, while the number of bytes read in is the actual length of your previous input. The length `strlen` calculates is the index of the first null byte in your input, wheras `read` returns the number of characters read.

This means that if your first input is `\x00AAAAAA`, `malloc(1)` will be called, yet read will read in 8 bytes. Since `buffer2` is allocated before `changeme`, overflowing into changeme is simple: The first input should start with a null byte, then have a large number of characters afterwards, then buffer2 will overlap with changeme.

The minimum size between allocations is 32 bytes in this situation, which means that if our 1st byte is a null byte (causing `malloc(1)`), then our second input should have 32 bytes of padding, then the next integer will overwrite changeme. This can be determined with two easy ways: dumping memory in gdb, or using the `cyclic` and `cyclic_find` functions provided by pwntools.

The only complexity left is the xor function. If we were required to set changme to a specific value, we would need to pay close attention to the result of the xor. However, since all that is required is changing the value, as long as our buffer overruns the location of changeme in memory, we should have a solution.

A simple solve script is as follows:
```
from pwn import *
p = process("./strlenvsread")
p.sendline(b"\x00" + b"A" * 254)
p.sendline(b"o" * 32 + p32(1337))

p.interactive()
```
