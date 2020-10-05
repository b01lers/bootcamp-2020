## Solution for: Link Battle

### Concept

This is a challenge with a little bit of nuance. We need to remember how dynamic linking works and apply that knowledge to some light reverse engineering.

### Solve

We get a shared library, `libflaggen.so` and nothing else. Intuition should point you in the direction of "what is in this .so?" 

We can get information about it with readelf:

```sh
$ readelf -s ./libflaggen.so
Symbol table '.dynsym' contains 9 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
     6: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
     7: 00000000000040b8     4 OBJECT  GLOBAL DEFAULT   23 g_threadsafe
     8: 00000000000012c8   132 FUNC    GLOBAL DEFAULT   12 getflag

Symbol table '.symtab' contains 63 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000200     0 SECTION LOCAL  DEFAULT    1 
     2: 0000000000000238     0 SECTION LOCAL  DEFAULT    2 
     3: 0000000000000260     0 SECTION LOCAL  DEFAULT    3 
     4: 0000000000000338     0 SECTION LOCAL  DEFAULT    4 
     5: 0000000000000440     0 SECTION LOCAL  DEFAULT    5 
     6: 0000000000000458     0 SECTION LOCAL  DEFAULT    6 
     7: 0000000000000478     0 SECTION LOCAL  DEFAULT    7 
     8: 0000000000000520     0 SECTION LOCAL  DEFAULT    8 
     9: 0000000000001000     0 SECTION LOCAL  DEFAULT    9 
    10: 0000000000001020     0 SECTION LOCAL  DEFAULT   10 
    11: 0000000000001050     0 SECTION LOCAL  DEFAULT   11 
    12: 0000000000001060     0 SECTION LOCAL  DEFAULT   12 
    13: 000000000000134c     0 SECTION LOCAL  DEFAULT   13 
    14: 0000000000002000     0 SECTION LOCAL  DEFAULT   14 
    15: 0000000000002058     0 SECTION LOCAL  DEFAULT   15 
    16: 0000000000002090     0 SECTION LOCAL  DEFAULT   16 
    17: 0000000000003df0     0 SECTION LOCAL  DEFAULT   17 
    18: 0000000000003df8     0 SECTION LOCAL  DEFAULT   18 
    19: 0000000000003e00     0 SECTION LOCAL  DEFAULT   19 
    20: 0000000000003fe0     0 SECTION LOCAL  DEFAULT   20 
    21: 0000000000004000     0 SECTION LOCAL  DEFAULT   21 
    22: 0000000000004040     0 SECTION LOCAL  DEFAULT   22 
    23: 00000000000040b0     0 SECTION LOCAL  DEFAULT   23 
    24: 0000000000000000     0 SECTION LOCAL  DEFAULT   24 
    25: 0000000000000000     0 SECTION LOCAL  DEFAULT   25 
    26: 0000000000000000     0 SECTION LOCAL  DEFAULT   26 
    27: 0000000000000000     0 SECTION LOCAL  DEFAULT   27 
    28: 0000000000000000     0 SECTION LOCAL  DEFAULT   28 
    29: 0000000000000000     0 SECTION LOCAL  DEFAULT   29 
    30: 0000000000000000     0 SECTION LOCAL  DEFAULT   30 
    31: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS /nix/store/rclksjxdjgp6y6
    32: 0000000000001060     0 FUNC    LOCAL  DEFAULT   12 deregister_tm_clones
    33: 0000000000001090     0 FUNC    LOCAL  DEFAULT   12 register_tm_clones
    34: 00000000000010d0     0 FUNC    LOCAL  DEFAULT   12 __do_global_dtors_aux
    35: 00000000000040b0     1 OBJECT  LOCAL  DEFAULT   23 completed.7381
    36: 0000000000003df8     0 OBJECT  LOCAL  DEFAULT   18 __do_global_dtors_aux_fin
    37: 0000000000001110     0 FUNC    LOCAL  DEFAULT   12 frame_dummy
    38: 0000000000003df0     0 OBJECT  LOCAL  DEFAULT   17 __frame_dummy_init_array_
    39: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS flag.c
    40: 00000000000040c0    12 OBJECT  LOCAL  DEFAULT   23 start_state
    41: 00000000000040d0    12 OBJECT  LOCAL  DEFAULT   23 lfsr
    42: 0000000000004060    79 OBJECT  LOCAL  DEFAULT   22 fflag
    43: 0000000000001115    89 FUNC    LOCAL  DEFAULT   12 init_galois
    44: 000000000000116e   346 FUNC    LOCAL  DEFAULT   12 galois
    45: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS /nix/store/rclksjxdjgp6y6
    46: 000000000000214c     0 OBJECT  LOCAL  DEFAULT   16 __FRAME_END__
    47: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS 
    48: 000000000000134c     0 FUNC    LOCAL  DEFAULT   13 _fini
    49: 0000000000004040     0 OBJECT  LOCAL  DEFAULT   22 __dso_handle
    50: 0000000000003e00     0 OBJECT  LOCAL  DEFAULT   19 _DYNAMIC
    51: 0000000000002058     0 NOTYPE  LOCAL  DEFAULT   15 __GNU_EH_FRAME_HDR
    52: 00000000000040b0     0 OBJECT  LOCAL  DEFAULT   22 __TMC_END__
    53: 0000000000004000     0 OBJECT  LOCAL  DEFAULT   21 _GLOBAL_OFFSET_TABLE_
    54: 0000000000001000     0 FUNC    LOCAL  DEFAULT    9 _init
    55: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@@GLIBC_2.2.5
    56: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
    57: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@@GLIBC_2.2.5
    58: 00000000000040b8     4 OBJECT  GLOBAL DEFAULT   23 g_threadsafe
    59: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    60: 00000000000012c8   132 FUNC    GLOBAL DEFAULT   12 getflag
    61: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
    62: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@GLIBC_2.2
```

Remembering that for us to use anything in a shared object, it does need to export a symbol, we can look through this list for anything marked `GLOBAL`. One stands out, `getflag`. 

The second thing besides a symbol we need to call a function from a shared object is the prototype. Let's go disassemble this function to see if we can figure out what its prototype is.

```
   0x00000000000012c8 <+0>:	push   rbp
   0x00000000000012c9 <+1>:	mov    rbp,rsp
   0x00000000000012cc <+4>:	push   rbx
   0x00000000000012cd <+5>:	sub    rsp,0x38
   0x00000000000012d1 <+9>:	mov    DWORD PTR [rbp-0x34],edi
   0x00000000000012d4 <+12>:	cmp    DWORD PTR [rbp-0x34],0x1a0a
```

This function prologue tells us we are passing in one argument (all we access is edi [lower 32 bits of rdi] and we move it onto the stack as a DWORD, which is 32 bits). We actually don't need to figure out the return value, we can typically just use `int` and we'll end up with an incompatible type. Luckily, unless the return type matters/we need to use it, this is perfectly fine. 

Now, we can write a tiny driver:

```c
#include <stdio.h>
#include <stdlib.h>

extern int getflag(int);

int main() {
	printf("%d\n", getflag(0));
}
```

(the printf is just so we can examine the return value in case it matters)

And compile it with:
```sh
$ gcc -L . -o test test.c -lflaggen
```

We can run with: `LD_LIBRARY_PATH=. ./test`

Now you'll notice that we do not jut get a flag, and the return value is zero. Why is this? We'll need to look a *little* further into the `getflag` function to figure that out. 

```
   0x00000000000012d4 <+12>:	cmp    DWORD PTR [rbp-0x34],0x1a0a
   0x00000000000012db <+19>:	jne    0x1340 <getflag+120>
   0x00000000000012dd <+21>:	lea    rax,[rip+0xd1c]        # 0x2000
```

First of all, remember when we identified `edi` as a single `int` argument? Well, we're comparing it to `0x1a0a`. If it isn't equal, we jump way down to the bottom of the function. Probably, we want to pass this check! `Next we have `lea rax, [rip+0xd1c]`. We can look at that spot in gdb:

```sh
> x/s 0x2000
0x2000:	"If you're reverse engineering me past this point...you're doing the challenge wrong!"
```

I don't want people getting stuck in my shitty decryption algorithm. Just call the function with `0x1a0a` and you'll get the flag!



