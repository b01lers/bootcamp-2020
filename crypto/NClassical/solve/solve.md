# Solution for Totem
## Concept
Introduction to Classical Ciphers and Encoding Schemes

## Solution

What is given: `template.py`

To solve this challenge you just need to fill in the four functions and then run it to get the flag.

The four functions are as follows:

### Bacon<br>
*For reference: [Bacon's Cipher Wiki Entry](https://en.wikipedia.org/wiki/Bacon%27s_cipher#Cipher_details)*<br>
Bacon's cipher takes the alphabet and encodes each letter to a 5 bit binary number using A and B, where A = 0 and B = 1. Noted in the source, this is the bacon's version where U != V and I != J to avoid any ambiguous decryptions. For example, `A` would become `AAAAA = 0b00000 = 0` and `Z` would become `BBAAB = 0b11001 = 25`. The only import being used to complete this is the string `ascii_lowercase` from the `string` module, which is just the lower case alphabet as a string.
```python
def bacon(s):
    dec = ''
    #Breaking up the string into groupings of 5
    groupings = [s[idx:idx+5] for idx in range(0,len(s),5)]
    for group in groupings:
        binString = group.replace('A','0').replace('B','1') #change to 1's and 0's
        val = int(binString,2) #base2 to base10
        dec += ascii_lowercase[val] #add the according letter from the alphabet
    return dec
``` 

### ROT13<br>
*For reference: [ROT13 Wiki Entry](https://en.wikipedia.org/wiki/ROT13)*<br>
Given by the name, ROT13, it means a rotation by 13 of the alphabet. So instead of A being the first letter it would instead be N, B would be O, and so on. Also, if you didn't notice the ROT13 function is its own inverse so ROT13'ing something twice will undo its shift. My solution in `solve.py` uses the `codecs` library to complete this function, but since the shift is always by 13 you could just write your own function to map the shifted letters back.
```python
def rot13(s):
    return codecs.decode(s,"rot_13")
```
**or**
```python
def rot13(s):
    dec = ''
    normal = ascii_lowercase
    shifted = ascii_lowercase[13::]+ascii_lowercase[:13:] #Alphabet starting with N
    for char in s:
        dec += normal[shifted.index(char)] #Map the shifted alphabet back to the normal alphabet
    return dec
```

### Atbash<br>
*For reference: [Atbash Wiki Entry](https://en.wikipedia.org/wiki/Atbash#Encryption)*<br>
Atbash is a substitution cipher where the normal alphabet is mapped to the reverse of the alphabet. For example, A = Z, B = Y, ... , M = N. The solution will look similar to the second version of the rot13 function above.
```python
def atbash(s):
    dec = ''
    normal = ascii_lowercase
    rev = ascii_lowercase[::-1] #reversed alphabet
    for char in s:
        dec += normal[rev.index(char)] #map the reverse back to the normal alphabet
    return dec
```

### Base64<br>
*For reference: [Base64 Wiki Entry](https://en.wikipedia.org/wiki/Base64)*<br>
Base64 is an encoding scheme that converts data into a ASCII string representation of that data. To solve, I used the `base64` module's decode function, you can also use the `codecs` module to do this. 
```python
def Base64(s):
    return base64.b64encode(s.encode()).decode()
```

