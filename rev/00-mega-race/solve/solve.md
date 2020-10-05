## Solution for: Mega Race

### Concept

This challenge is another step up. There are two main skills this challenge focuses on. First is narrowing in on the important parts of a larger binary and ignoring the noise to not waste time reversing parts that won't lead to a flag. Second is analyzing slightly more complex code constructs involving iteration and modification of data as well as pointers.

### Solve

If we run the program, we are prompted for a password. We don't know it, so when we enter some "password" string, we get a message:

```
Sorry kid, you don't have what it takes...but you better show us anyway!
WELCOME. TO. MEGA RACE!
POTENTIAL EPILEPSY WARNING. YOU HAVE UNTIL THE COUNTDOWN TO HIT CTRL+C OR CLOSE YOUR TERMINAL
```

Seriously, heed the epilepsy warning. Anyway, this is followed by a countdown and a game where you drive a motorcycle through barrels. If you hit one, the number of barrels you have to navigate around increases. So...where's the flag?

Lets open the program in GDB and disassemble the main function:

```
> gdb -q ./mega-race
gdb> disassemble main
   0x00000000004023bd <+0>:	push   rbp
   0x00000000004023be <+1>:	mov    rbp,rsp
   0x00000000004023c1 <+4>:	call   0x401bd0 <init_race>
   0x00000000004023c6 <+9>:	xor    eax,0x1
   0x00000000004023c9 <+12>:	test   al,al
   0x00000000004023cb <+14>:	je     0x4023d4 <main+23>
   0x00000000004023cd <+16>:	mov    eax,0x1
   0x00000000004023d2 <+21>:	jmp    0x4023e3 <main+38>
   0x00000000004023d4 <+23>:	call   0x402330 <begin_race>
   0x00000000004023d9 <+28>:	call   0x4011a0 <endwin@plt>
   0x00000000004023de <+33>:	mov    eax,0x0
   0x00000000004023e3 <+38>:	pop    rbp
   0x00000000004023e4 <+39>:	ret   
```

We have a few functions here called from main. Lets go ahead and look at init_race. 
```
   0x0000000000401bd0 <+0>:	push   rbp
   0x0000000000401bd1 <+1>:	mov    rbp,rsp
   0x0000000000401bd4 <+4>:	mov    eax,0x0
   0x0000000000401bd9 <+9>:	call   0x4013eb <asdfghjkl>
   0x0000000000401bde <+14>:	xor    eax,0x1
   0x0000000000401be1 <+17>:	test   al,al
   0x0000000000401be3 <+19>:	je     0x401c88 <init_race+184>
   0x0000000000401be9 <+25>:	lea    rdi,[rip+0x1540]        # 0x403130
   0x0000000000401bf0 <+32>:	call   0x401040 <puts@plt>
   0x0000000000401bf5 <+37>:	call   0x401443 <countdown>
   0x0000000000401bfa <+42>:	call   0x401a2c <init_curses>
   0x0000000000401bff <+47>:	mov    rax,QWORD PTR [rip+0x33f2]        # 0x404ff8
   0x0000000000401c06 <+54>:	mov    rax,QWORD PTR [rax]
   0x0000000000401c09 <+57>:	test   rax,rax
   0x0000000000401c0c <+60>:	je     0x401c22 <init_race+82>
   0x0000000000401c0e <+62>:	mov    rax,QWORD PTR [rip+0x33e3]        # 0x404ff8
   0x0000000000401c15 <+69>:	mov    rax,QWORD PTR [rax]
   0x0000000000401c18 <+72>:	movzx  eax,WORD PTR [rax+0x4]
   0x0000000000401c1c <+76>:	cwde   
   0x0000000000401c1d <+77>:	add    eax,0x1
   0x0000000000401c20 <+80>:	jmp    0x401c27 <init_race+87>
   0x0000000000401c22 <+82>:	mov    eax,0xffffffff
   0x0000000000401c27 <+87>:	mov    DWORD PTR [rip+0x346f],eax        # 0x40509c <maxy>
   0x0000000000401c2d <+93>:	mov    rax,QWORD PTR [rip+0x33c4]        # 0x404ff8
   0x0000000000401c34 <+100>:	mov    rax,QWORD PTR [rax]
   0x0000000000401c37 <+103>:	test   rax,rax
   0x0000000000401c3a <+106>:	je     0x401c50 <init_race+128>
   0x0000000000401c3c <+108>:	mov    rax,QWORD PTR [rip+0x33b5]        # 0x404ff8
   0x0000000000401c43 <+115>:	mov    rax,QWORD PTR [rax]
   0x0000000000401c46 <+118>:	movzx  eax,WORD PTR [rax+0x6]
   0x0000000000401c4a <+122>:	cwde   
   0x0000000000401c4b <+123>:	add    eax,0x1
   0x0000000000401c4e <+126>:	jmp    0x401c55 <init_race+133>
   0x0000000000401c50 <+128>:	mov    eax,0xffffffff
   0x0000000000401c55 <+133>:	mov    DWORD PTR [rip+0x343d],eax        # 0x405098 <maxx>
   0x0000000000401c5b <+139>:	mov    rax,QWORD PTR [rip+0x3396]        # 0x404ff8
   0x0000000000401c62 <+146>:	mov    rax,QWORD PTR [rax]
   0x0000000000401c65 <+149>:	mov    esi,0x1
   0x0000000000401c6a <+154>:	mov    rdi,rax
   0x0000000000401c6d <+157>:	call   0x4010f0 <wtimeout@plt>
   0x0000000000401c72 <+162>:	call   0x4014c2 <getcycle>
   0x0000000000401c77 <+167>:	call   0x4017c0 <getbarrel>
   0x0000000000401c7c <+172>:	call   0x401a8b <initbarrels>
   0x0000000000401c81 <+177>:	mov    eax,0x1
   0x0000000000401c86 <+182>:	jmp    0x401c99 <init_race+201>
   0x0000000000401c88 <+184>:	lea    rdi,[rip+0x1509]        # 0x403198
   0x0000000000401c8f <+191>:	call   0x401040 <puts@plt>
   0x0000000000401c94 <+196>:	mov    eax,0x0
   0x0000000000401c99 <+201>:	pop    rbp
   0x0000000000401c9a <+202>:	ret
```

This function name starts with init_ so chances are this does some....initialization! Luckily for us, this program isn't stripped, so we know what all the function names are. There's a little bit of logic between the function calls, but mostly we have a sequence of:

- asdfghjkl (???)
- printf (prints something out)
- countdown (probably does the countdown)
- init_curses (probably initializes ncurses)
- wtimeout (used by ncurses to make controls non-blocking)
- getcycle (probably gets the motorcycle)
- getbarrel (probably gets a barrel...we have an ascii art and there are barrels in the game)
- initbarrels (initializes barrels)

....you'll notice by now that having function names makes things pretty easy to get an overview without much effort. One of these, asdfghjkl stands out like a sore thumb. Lets look at it:

```
   0x00000000004013eb <+0>:	push   rbp
   0x00000000004013ec <+1>:	mov    rbp,rsp
   0x00000000004013ef <+4>:	sub    rsp,0x10
   0x00000000004013f3 <+8>:	lea    rdi,[rip+0x1c6c]        # 0x403066
   0x00000000004013fa <+15>:	mov    eax,0x0
   0x00000000004013ff <+20>:	call   0x4010a0 <printf@plt>
   0x0000000000401404 <+25>:	mov    edi,0x26
   0x0000000000401409 <+30>:	call   0x401385 <getpasswd>
   0x000000000040140e <+35>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401412 <+39>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401416 <+43>:	mov    rdi,rax
   0x0000000000401419 <+46>:	call   0x40132c <scram>
   0x000000000040141e <+51>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401422 <+55>:	lea    rsi,[rip+0x1c17]        # 0x403040 <pass>
   0x0000000000401429 <+62>:	mov    rdi,rax
   0x000000000040142c <+65>:	call   0x401130 <strcmp@plt>
   0x0000000000401431 <+70>:	test   eax,eax
   0x0000000000401433 <+72>:	jne    0x40143c <asdfghjkl+81>
   0x0000000000401435 <+74>:	mov    eax,0x1
   0x000000000040143a <+79>:	jmp    0x401441 <asdfghjkl+86>
   0x000000000040143c <+81>:	mov    eax,0x0
   0x0000000000401441 <+86>:	leave  
   0x0000000000401442 <+87>:	ret  
```

We have a print, a getpasswd function that returns a value that is then passed to a function called scram and strcmp'ed against something. 

getpasswd allocates some memory, calls fgets, and returns the allocated pointer, so this is almost certainly our password input. We know we probably want to pass the strcmp so lets look at the scram function to see how it modifies our input. I've commented the disassembly below because this is more in the weeds than just looking at function names.

```
# Set up stack frame
   0x000000000040132c <+0>:	push   rbp
   0x000000000040132d <+1>:	mov    rbp,rsp
# Get some stack space 0x20 in size
   0x0000000000401330 <+4>:	sub    rsp,0x20
# Place the first argument on the stack (pointer to our password string)
   0x0000000000401334 <+8>:	mov    QWORD PTR [rbp-0x18],rdi
   0x0000000000401338 <+12>:	mov    rax,QWORD PTR [rbp-0x18]
   0x000000000040133c <+16>:	mov    rdi,rax
# Get the length of our password string
   0x000000000040133f <+19>:	call   0x401070 <strlen@plt>
# Put the result of the strlen on the stack.
   0x0000000000401344 <+24>:	mov    QWORD PTR [rbp-0x8],rax
# Initialize loop counter and start loop
   0x0000000000401348 <+28>:	mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000401350 <+36>:	jmp    0x401377 <scram+75>

# Get our pointer to the password
   0x0000000000401352 <+38>:	mov    rdx,QWORD PTR [rbp-0x18]
# Get our loop counter
   0x0000000000401356 <+42>:	mov    rax,QWORD PTR [rbp-0x10]
# Add the current index (loop counter) to the password pointer to get
# the current character
   0x000000000040135a <+46>:	add    rax,rdx
# Put the current character into ecx
   0x000000000040135d <+49>:	movzx  ecx,BYTE PTR [rax]
   0x0000000000401360 <+52>:	mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000000401364 <+56>:	mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000401368 <+60>:	add    rax,rdx
# XOR the current character with 0x77
   0x000000000040136b <+63>:	xor    ecx,0x77
   0x000000000040136e <+66>:	mov    edx,ecx
# Store the XOR result back into the input character
   0x0000000000401370 <+68>:	mov    BYTE PTR [rax],dl
# Increment the loop counter
   0x0000000000401372 <+70>:	add    QWORD PTR [rbp-0x10],0x1
   0x0000000000401377 <+75>:	mov    rax,QWORD PTR [rbp-0x10]
# Check the loop counter against the string length
   0x000000000040137b <+79>:	cmp    rax,QWORD PTR [rbp-0x8]
   0x000000000040137f <+83>:	jb     0x401352 <scram+38>
# Iterated for each character in input
   0x0000000000401381 <+85>:	nop
   0x0000000000401382 <+86>:	nop
   0x0000000000401383 <+87>:	leave  
   0x0000000000401384 <+88>:	ret   
```

Now, we have XORed each character in our password with 0x77. What do we compare it to? Our first argument, `rdi` to strcmp is the password we input, so we want to look at `rsi`, the second argument. We have a location relative to rip, stored at 0x403040. If we look at that location, we'll see:

`> x/48x 0x403040`

```
0x403040 <pass>:	0x10161b11	0x1947140c	0x03430510	0x03431b02
0x403050 <pass+16>:	0x0d194746	0x02470e28	0x44051628	0x441f0328
0x403060 <pass+32>:	0x2e223028	0x45000a56	0x5245544e	0x45485420
```

If we go ahead and de-little-endian that and assume the nullbyte in there does terminate the string we get something that isn't printable characters:

```
{0x11, 0x1b, 0x16, 0x10, 0xc, 0x14, 0x47, 0x19, 0x10, 0x5, 0x43, 0x3, 0x2, 0x1b, 0x43, 0x3, 0x46, 0x47, 0x19, 0xd, 0x28, 0xe, 0x47, 0x2, 0x28, 0x16, 0x5, 0x44, 0x28, 0x3, 0x1f, 0x44, 0x28, 0x30, 0x22, 0x2e, 0x56, 0xa, 0x0};
````

Luckily for us, we already got the key this is XOR'ed with. XOR each of these characters by 0x77 and we get:

`flag{c0ngr4tul4t10nz_y0u_ar3_th3_GUY!} `

We can use a script like this:
```python
KEY = 0x77
password_encoded = [0x11, 0x1b, 0x16, 0x10, 0xc, 0x14, 0x47, 0x19, 0x10, 0x5, 0x43, 0x3, 0x2, 0x1b, 0x43, 0x3, 0x46, 0x47, 0x19, 0xd, 0x28, 0xe, 0x47, 0x2, 0x28, 0x16, 0x5, 0x44, 0x28, 0x3, 0x1f, 0x44, 0x28, 0x30, 0x22, 0x2e, 0x56, 0xa]
for ch in password_encoded:
    print(chr(ch ^ KEY), end="")
```
