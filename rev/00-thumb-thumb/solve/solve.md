## Solution for: Thumb Thumb

### Concept

This challenge is a baby step up. The flag is assigned one character at a a time to a stack array in a function.

### Solve

Welcome to challenge 2! While #1 was solvable without looking at any code or actual reversing, this one will make us look (only a little) at some assembly.

So we have an executable, running `file` tells us it is a 64-bit ELF.

If we run the program, we'll see a _beautiful_ ASCII art of a _beautiful_ thumb-thumb bouncing around the screen at an ever-increasing speed.

Running `strings` or `readelf` won't get us anywhere this time, and running the program doesn't seem to do anything that'll get us the flag. So it's time to open up `gdb`. If you have never used a debugger before, refer to the gdb primer in the 2020 Bootcamp Lessons wiki under [b01lers](https://github.com/b01lers). I won't be going in depth on what it is or how it works here, I'll just be using it.

`gdb -q ./thumb-thumb`

This will load gdb with our executable. Next, run `disassemble main`.

Usually (not always but pretty close to it), `main` will be the entry point to a program, so that's a pretty good place to start reversing the program. The `disas` command will just print out the disassembly of the program. 


This is pretty simple stuff, nice! So we see at the top we have a _function prologue_. This is code the [_SystemV calling convention_](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI) uses to set up _stack frames_. This code is:

```
   0x0000000000401bb7 <+0>:	push   rbp
   0x0000000000401bb8 <+1>:	mov    rbp,rsp
   0x0000000000401bbb <+4>:	sub    rsp,0x10
```

So what happens here is we `push rbp`, which saves the base pointer of the previous _stack frame_ on top of the stack. We then copy the previous stack frame's _stack pointer_ into the _base pointer register_. For more information on these registers and stack frames, see the Linux Assembly Primer under [b01lers](https://github.com/b01lers). After setting up the stack frame, we subtract 0x10 from `rsp`, which grabs 16 bytes of stack space in this stack frame.


```

   0x0000000000401bbf <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x0000000000401bc2 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
```
Moving on, we save `argc` and `argv` (which are the first 2 arguments to main by convention. Main is just a function, so arguments are passed the same as any other function: the first (up to) six in registers `rdi, rsi, rdx, rcx, r8, and r9`, and the rest on the stack. Since main's arguments are determined by the platform, we know for sure that edi is `argc` and `rsi` is argv.



```
   0x0000000000401bc6 <+15>:	call   0x4011c2 <thumblings_assemble>
   0x0000000000401bcb <+20>:	call   0x401614 <thumblings_engage>
   0x0000000000401bd0 <+25>:	call   0x401b57 <thumblings_attack>
   0x0000000000401bd5 <+30>:	call   0x401bab <thumblings_retreat>
   0x0000000000401bda <+35>:	mov    eax,0x0
   0x0000000000401bdf <+40>:	leave  
   0x0000000000401be0 <+41>:	ret
```
We then call four functions and return zero. Remember that whatever value is in `rax` when we return from a function is the return value of that function.

Done! We know exactly what main is doing. Now lets go ahead and look at those functions:

`disassemble thumblings_assemble`


As soon as you disassemble this function you should realize this is the magic cookie. We have prologue code :

```
   0x00000000004011c2 <+0>:	push   rbp
   0x00000000004011c3 <+1>:	mov    rbp,rsp
   0x00000000004011c6 <+4>:	add    rsp,0xffffffffffffff80
   0x00000000004011ca <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000004011d3 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004011d7 <+21>:	xor    eax,eax
```


Notice that this time when we grab stack space, we add `0xffffffffffffff80` instead of subtracting 0x80 as we'd expect. Why? Twos compliment! This is actually adding -0x80 to rsp, so it is still a decrement, just in a roundabout way. After getting some stack space we move fs:0x28 into rax. This is the compiler putting in what is called a _stack canary_, which you can read more about in the pwn lessons. For now, we'll ignore that. The important part is this:

```
   0x00000000004011d9 <+23>:	mov    DWORD PTR [rbp-0x70],0x66
   0x00000000004011e0 <+30>:	mov    DWORD PTR [rbp-0x1c],0x75
   0x00000000004011e7 <+37>:	mov    DWORD PTR [rbp-0x60],0x7b
   0x00000000004011ee <+44>:	mov    DWORD PTR [rbp-0x54],0x6e
   0x00000000004011f5 <+51>:	mov    DWORD PTR [rbp-0x4c],0x5f
   0x00000000004011fc <+58>:	mov    DWORD PTR [rbp-0x18],0x6d
   0x0000000000401203 <+65>:	mov    DWORD PTR [rbp-0x48],0x30
   0x000000000040120a <+72>:	mov    DWORD PTR [rbp-0x34],0x33
   0x0000000000401211 <+79>:	mov    DWORD PTR [rbp-0x20],0x68
   0x0000000000401218 <+86>:	mov    DWORD PTR [rbp-0x18],0x6d
   0x000000000040121f <+93>:	mov    DWORD PTR [rbp-0x14],0x62
   0x0000000000401226 <+100>:	mov    DWORD PTR [rbp-0x40],0x72
   0x000000000040122d <+107>:	mov    DWORD PTR [rbp-0x3c],0x5f
   0x0000000000401234 <+114>:	mov    DWORD PTR [rbp-0x38],0x62
   0x000000000040123b <+121>:	mov    DWORD PTR [rbp-0x2c],0x74
   0x0000000000401242 <+128>:	mov    DWORD PTR [rbp-0x50],0x64
   0x0000000000401249 <+135>:	mov    DWORD PTR [rbp-0x28],0x5f
   0x0000000000401250 <+142>:	mov    DWORD PTR [rbp-0x44],0x75
   0x0000000000401257 <+149>:	mov    DWORD PTR [rbp-0x24],0x74
   0x000000000040125e <+156>:	mov    DWORD PTR [rbp-0x58],0x33
   0x0000000000401265 <+163>:	mov    DWORD PTR [rbp-0x6c],0x6c
   0x000000000040126c <+170>:	mov    DWORD PTR [rbp-0x68],0x61
   0x0000000000401273 <+177>:	mov    DWORD PTR [rbp-0x64],0x67
   0x000000000040127a <+184>:	mov    DWORD PTR [rbp-0x5c],0x73
   0x0000000000401281 <+191>:	mov    DWORD PTR [rbp-0x20],0x68
   0x0000000000401288 <+198>:	mov    DWORD PTR [rbp-0x14],0x62
   0x000000000040128f <+205>:	mov    DWORD PTR [rbp-0x30],0x73
   0x0000000000401296 <+212>:	mov    DWORD PTR [rbp-0x10],0x35
   0x000000000040129d <+219>:	mov    DWORD PTR [rbp-0xc],0x7d
   0x00000000004012a4 <+226>:	mov    DWORD PTR [rbp-0x74],0x0
```

This code is sequentially placing a bunch of values into the stack space we just got from decrementing `rsp`. The astute RE enthusiast will notice these are all ascii values. If we look at the ASCII value of 0x66, it is 'f'. Now, the rest of these aren't in order after 'f', so we'll need to look at their offsets from `rbp` to put them back in order. If we reorder the assignments to be in order of address (which is the way they'd be in memory, we get:

```
   0x00000000004011d9 <+23>:	mov    DWORD PTR [rbp-0x70],0x66
   0x00000000004011e0 <+30>:	mov    DWORD PTR [rbp-0x6c],0x6c
   0x00000000004011e7 <+37>:	mov    DWORD PTR [rbp-0x68],0x61
   0x00000000004011ee <+44>:	mov    DWORD PTR [rbp-0x64],0x67
   0x00000000004011f5 <+51>:	mov    DWORD PTR [rbp-0x60],0x7b
   0x00000000004011fc <+58>:	mov    DWORD PTR [rbp-0x5c],0x73
   0x0000000000401203 <+65>:	mov    DWORD PTR [rbp-0x58],0x33
   0x000000000040120a <+72>:	mov    DWORD PTR [rbp-0x54],0x6e
   0x0000000000401211 <+79>:	mov    DWORD PTR [rbp-0x50],0x64
   0x0000000000401218 <+86>:	mov    DWORD PTR [rbp-0x4c],0x5f
   0x000000000040121f <+93>:	mov    DWORD PTR [rbp-0x48],0x30
   0x0000000000401226 <+100>:	mov    DWORD PTR [rbp-0x44],0x75
   0x000000000040122d <+107>:	mov    DWORD PTR [rbp-0x40],0x72
   0x0000000000401234 <+114>:	mov    DWORD PTR [rbp-0x3c],0x5f
   0x000000000040123b <+121>:	mov    DWORD PTR [rbp-0x38],0x62
   0x0000000000401242 <+128>:	mov    DWORD PTR [rbp-0x34],0x33
   0x0000000000401249 <+135>:	mov    DWORD PTR [rbp-0x30],0x73
   0x0000000000401250 <+142>:	mov    DWORD PTR [rbp-0x2c],0x74
   0x0000000000401257 <+149>:	mov    DWORD PTR [rbp-0x28],0x5f
   0x000000000040125e <+156>:	mov    DWORD PTR [rbp-0x24],0x74
   0x0000000000401265 <+163>:	mov    DWORD PTR [rbp-0x20],0x68
   0x000000000040126c <+170>:	mov    DWORD PTR [rbp-0x1c],0x75
   0x0000000000401273 <+177>:	mov    DWORD PTR [rbp-0x18],0x6d
   0x000000000040127a <+184>:	mov    DWORD PTR [rbp-0x14],0x62
   0x0000000000401281 <+191>:	mov    DWORD PTR [rbp-0x10],0x35
   0x0000000000401288 <+198>:	mov    DWORD PTR [rbp-0xc],0x7d
   0x000000000040128f <+205>:	mov    DWORD PTR [rbp-0x74],0x0
```

Translate the hex here to ASCII characters and we get:

`flag{s3nd_0ur_b3st_thumb5}`


### Alternate solve technique

There's another (potentially) easier way to solve this that avoids the manual labor of reordering the array: _actually_ use GDB. We know that at `0x000000000040128f` the array is fully formed. If we restart gdb:

`gdb -q ./thumb-thumb`

Set a breakpoint with `break *0x00000000004012a4`, run to the point with `continue` and print the array with `x/128c $rbp-0x70`.





