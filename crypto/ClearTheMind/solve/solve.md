## Solution for: Clear The Mind

### Concept

This challenge is meant to demonstrate the small-exponent vulnerability in (textbook) RSA

### Solve

This is the information we are given:
```
n = 102346477809188164149666237875831487276093753138581452189150581288274762371458335130208782251999067431416740623801548745068435494069196452555130488551392351521104832433338347876647247145940791496418976816678614449219476252610877509106424219285651012126290668046420434492850711642394317803367090778362049205437

c = 4458558515804625757984145622008292910146092770232527464448604606202639682157127059968851563875246010604577447368616002300477986613082254856311395681221546841526780960776842385163089662821

e = 3
```

We notice straightaway that `e` is 3 instead of the more typical value of 65537.

Recall that RSA works by raising some plaintext <img src="https://render.githubusercontent.com/render/math?math=p"> to a power <img src="https://render.githubusercontent.com/render/math?math=e"> modulo some <img src="https://render.githubusercontent.com/render/math?math=n">, that is, <img src="https://render.githubusercontent.com/render/math?math=c = p^e\quad(\text{mod}\,n)">

Now notice that our ciphertext, <img src="https://render.githubusercontent.com/render/math?math=c">, is significantly less than <img src="https://render.githubusercontent.com/render/math?math=n"> - since <img src="https://render.githubusercontent.com/render/math?math=c = p^e < n">, that means that <img src="https://render.githubusercontent.com/render/math?math=p = \sqrt[3]{c}">, and we can decrypt the ciphertext by just computing the cube root!

You can use a tool like Wolfram|Alpha to compute the cube root, then from bytes to ascii, or you can use Python (or another language of your choice)

In Python, we would have
```
def nth_root(x, n):
    hi = 1
    while hi ** n <= x:
        hi *= 2
    lo = hi // 2
    while lo < hi:
        mid = (lo + hi) // 2
        mid_nth = mid ** n
        if lo < mid and mid_nth < x:
            lo = mid
        elif hi > mid and mid_nth > x:
            hi = mid
        else:
            return mid
        return mid + 1

n = 102346477809188164149666237875831487276093753138581452189150581288274762371458335130208782251999067431416740623801548745068435494069196452555130488551392351521104832433338347876647247145940791496418976816678614449219476252610877509106424219285651012126290668046420434492850711642394317803367090778362049205437
c = 4458558515804625757984145622008292910146092770232527464448604606202639682157127059968851563875246010604577447368616002300477986613082254856311395681221546841526780960776842385163089662821
e = 3

m = nth_root(c, e)
# convert the result into bytes, then translate to ascii
print(bytearray.fromhex(hex(m)[2:]).decode())
```

The tricky bit here is that we have to write our own function to compute the cube root, as the numbers here are too big, and if use something like `c ** (1. / 3)` we don't get a precise result

flag: `flag{w3_need_7o_g0_d3ep3r}`

