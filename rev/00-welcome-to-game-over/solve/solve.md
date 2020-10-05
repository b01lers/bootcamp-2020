## Solution for: Welcome to Game Over

### Concept

This challenge is about as dirt simple as it gets: hide the flag somewhere in the binary so you have to find it.

### Solve

To solve, run `strings` on `game-over`. 

Strings is a super simple utility that scans for any continuous sequence of valid ASCII characters longer than N in a file (default is 4) and prints them all out.

You'll see a bunch of symbols from the program but if you look closely you'll also see:

`flag{welc0me_to_th3_game<FIND_THE_REST_OF_THE_FLAG_IN_FUNCTION_NAMES>}`

Now, the other part of the flag does appear in strings, because any non-stripped symbols will appear in strings and function names are no exception, but for the sake of following the challenge lets dump the names of the functions in the binary:

`readelf -s ./game-over | grep "FUNC"`

ELF (Executable and Linkable Format, more info [here](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)) files are pretty complicated to the new reverser, but suffice to say for the purposes of this challenge:

1. There is a header for the ELF file.
2. The ELF file header tells the `loader` and `linker` important informtion about the program, including the _offset_ of the section headers and the _number_ of section headers.
3. These section headers contain all kinds of different stuff, but we are concerned with the `.symtab` header. This contains the location and size of the ELF symbol table, which has the offsets, names, and scopes of all the functions and objects in the ELF file.
4. We want to find a function name, so we want to dump the symbol table and look at all the FUNC (function) entries to find one that looks like the rest of the flag.

`readelf` is a tool made for printing out any and all possible things you might want to know about a given ELF file, so we will use it with `-s --syms              Display the symbol table` to do just what the option says. We'll then filter for the FUNC entries and look at them:

```
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.2.5 (2)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.2.5 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fflush@GLIBC_2.2.5 (2)
     8: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND usleep@GLIBC_2.2.5 (2)
    35: 00000000004010c0     0 FUNC    LOCAL  DEFAULT   13 deregister_tm_clones
    36: 00000000004010f0     0 FUNC    LOCAL  DEFAULT   13 register_tm_clones
    37: 0000000000401130     0 FUNC    LOCAL  DEFAULT   13 __do_global_dtors_aux
    40: 0000000000401160     0 FUNC    LOCAL  DEFAULT   13 frame_dummy
    51: 0000000000401370     1 FUNC    GLOBAL DEFAULT   13 __libc_csu_fini
    52: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND putchar@@GLIBC_2.2.5
    55: 000000000040129a    20 FUNC    GLOBAL DEFAULT   13 _my_little_thumbling
    56: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.2.5
    58: 0000000000401374     0 FUNC    GLOBAL HIDDEN    14 _fini
    59: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strlen@@GLIBC_2.2.5
    60: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.2.5
    61: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@@GLIBC_
    66: 0000000000401310    93 FUNC    GLOBAL DEFAULT   13 __libc_csu_init
    67: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND fflush@@GLIBC_2.2.5
    69: 0000000000401090    43 FUNC    GLOBAL DEFAULT   13 _start
    71: 00000000004012ae    90 FUNC    GLOBAL DEFAULT   13 main
    72: 0000000000401162   194 FUNC    GLOBAL DEFAULT   13 flashprint
    74: 0000000000401000     0 FUNC    GLOBAL HIDDEN    11 _init
    75: 0000000000401224   118 FUNC    GLOBAL DEFAULT   13 funprint
    76: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND usleep@@GLIBC_2.2.5
```

And voila, that `_my_little_thumbling` looks like the end of the flag to me! Put it together and we get

`flag{welc0me_to_th3_game_my_little_thumbling}`
