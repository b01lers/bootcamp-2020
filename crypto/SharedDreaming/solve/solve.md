## Solution for: Shared Dreaming

### Concept
Properties of XOR and Known-plaintext attacks on XOR

### Solution

What is given:
```
Hint 1: a1 ⊕ a2 ⊕ a3 ⊕ a4 = 8ba4c4dfce33fd6101cf5c56997531c024a10f1dc323eb7fe3841ac389747fb90e3418f90011ef2610fa3636cd6cf0002d19faa30d39161fbd45cc58abff6a84
Hint 2: a2 ⊕ a3 ⊕ a4 = f969375145322aba697ce9b4e00aa88e81ffe5c306b1b98148f33c4581b2ac39bc95f13b27c39f2311a590b7e27cdbdb7599f615acd70c45378e44fb319b8cb6
Hint 3: a1 ⊕ a3 = 855249b385f7b1d9923f71feb3bdee1032963ab51aa7b9d89a20c08c381e77890aa8849702d8791f8e636e833928ba6ea44c5f261983b7e29bd82e44b77fe03b
Ciphertext: flag ⊕ a3 ⊕ RandByte = f694bc3d12a0673aead8fc4fdf964f5ec0c1d938e722bf333000f300088ead0dec1e7e03720331098068c13a066ca9bca89850a8ee67feb8471af5f47b4c0f13
```

#### Solution Proof of Concept
Let's first indentify what we need to retrieve to find the flag from the ciphertext, where OTP() is a single byte one-time pad.

![formula](https://render.githubusercontent.com/render/math?math=$C=flag{\oplus}a_{3}{\oplus}RandByte$)

If we are able to retrieve a3 and the OTPbyte then computing the flag is trival, due to the following properties of XOR:

 Property  | Example | 
| -------- | -------- 
| Self-Inverse     | ![formula](https://render.githubusercontent.com/render/math?math=A{\oplus}A=0) |
| Identity Element | ![formula](https://render.githubusercontent.com/render/math?math=$A{\oplus}0=A$) |
| Commutitvity | ![formula](https://render.githubusercontent.com/render/math?math=$A{\oplus}B=B{\oplus}A$) |
| Associativity | ![formula](https://render.githubusercontent.com/render/math?math=$A{\oplus}(B{\oplus}C)=(A{\oplus}B){\oplus}C$) |

Determining a3
---
In `output.txt` we are given three equations and our objective is to determine the value of a3. If we take the second and third equations, replacing the literal values with b2 and b3 respectively:
![formula](https://render.githubusercontent.com/render/math?math=$a_{2}{\oplus}a_{3}{\oplus}a_{4}=b_{2}{\quad}{\textrm{and}}{\quad}a_{1}{\oplus}a_{3}=b_{3}$)
XOR'ing these two equations together gives us:
![formula](https://render.githubusercontent.com/render/math?math=$(a_{2}{\oplus}a_{3}{\oplus}a_{4}){\oplus}(a_{1}{\oplus}a_{3})=a_{2}{\oplus}a_{4}{\oplus}a_{1}=b_{2}{\oplus}b_{3}$)
Notice the two a3 terms will cancel due to Self-Inverse and Identity Element Properties. Now if we take a look at the first equation and the equation we just found we can see that if XOR the two together we obtain the value of a3, due to the same properties in the last step.
![formula](https://render.githubusercontent.com/render/math?math=$(a_{1}{\oplus}a_{2}{\oplus}a_{3}{\oplus}a_{4}){\oplus}(a_{2}{\oplus}a_{4}{\oplus}a_{1})=a_{3}=b_{1}{\oplus}b_{2}{\oplus}b_{3}$)

Determining the Random Character Pad Byte
---
 The reason we can easily determine the value of our pad, in this case, is for two reasons; it is a singular byte with a known range of values, which restricts the search space, and also because you know the flag format 'flag{.*}'. In knowing the flag format, this makes direct computation of the pad character trivial. If we consider the most significant byte (MSB) of the flag, m, the MSB of a3, a, and our unknown pad character, x; then we can express this as the following:
![formula](https://render.githubusercontent.com/render/math?math=$a{\oplus}x=m{\longrightarrow}x{\oplus}a{\oplus}a=m{\oplus}a{\longrightarrow}x=a{\oplus}m$)

Notice, we know `m`, the MSB of the flag as 'f', and `a`, the MSB of a3, here, thus making the direct computation of `x` trivial. 

Computation of the flag
---
To compute the flag we simply need to one-time pad the ciphertext with the character found in the last step and then XOR with the value found for a3. This yields the flag: `flag{1f_w3_4r3_g0nn4_p3rf0rm_1nc3pt10n_th3n_w3_n33d_1m4g1n4t10n}`


