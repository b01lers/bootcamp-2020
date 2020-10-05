# Given
h1 = bytearray.fromhex('8ba4c4dfce33fd6101cf5c56997531c024a10f1dc323eb7fe3841ac389747fb90e3418f90011ef2610fa3636cd6cf0002d19faa30d39161fbd45cc58abff6a84')
h2 = bytearray.fromhex('f969375145322aba697ce9b4e00aa88e81ffe5c306b1b98148f33c4581b2ac39bc95f13b27c39f2311a590b7e27cdbdb7599f615acd70c45378e44fb319b8cb6')
h3 = bytearray.fromhex('855249b385f7b1d9923f71feb3bdee1032963ab51aa7b9d89a20c08c381e77890aa8849702d8791f8e636e833928ba6ea44c5f261983b7e29bd82e44b77fe03b')
c = bytearray.fromhex('f694bc3d12a0673aead8fc4fdf964f5ec0c1d938e722bf333000f300088ead0dec1e7e03720331098068c13a066ca9bca89850a8ee67feb8471af5f47b4c0f13')

'''
First Step: Determining a3
h1 = a1 ⊕ a2 ⊕ a3 ⊕ a4
h2 = a2 ⊕ a3 ⊕ a4
h3 = a1 ⊕ a3

h2 ⊕ h3 = a2 ⊕ a3 ⊕ a4 ⊕ a1 ⊕ a3 = a2 ⊕ a4 ⊕ a1
h1 ⊕ h2 ⊕ h3 = a1 ⊕ a2 ⊕ a3 ⊕ a4 ⊕ a2 ⊕ a4 ⊕ a1 = a3
'''

# Let's define a function to xor these two values together

def xor(s1,s2):
	resultant = bytearray()
	for x,y in zip(s1,s2):
		resultant.append(x^y)
	return resultant

a3 = xor(h1,xor(h2,h3)) # h1 ⊕ h2 ⊕ h3 = a3
# Know we know that each char of the flag is also XOR'd w/ the same byte.  
# Theres only 256 so it is easily bruteforceable
# However...
# We know the flag format is 'flag' so we know that for our first byte, b1, of the flag the following constraint holds
# p, a3_b1, m_b1 = 'f'
# m_b1 ⊕ p = 'f'
# 'f' ⊕ a3_b1 = p

c = xor(c,a3)
RanChar = c[0] ^ ord('f')

# Now that we have the value of the char used and the value of a3 we can directly compute the flag
flag = bytearray()
for x in c:
	flag.append(x^RanChar)

print(flag)
