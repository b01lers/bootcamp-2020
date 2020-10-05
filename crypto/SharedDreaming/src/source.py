import os
from string import ascii_lowercase
from random import randint

flag = bytearray(b'flag{1f_w3_4r3_g0nn4_p3rf0rm_1nc3pt10n_th3n_w3_n33d_1m4g1n4t10n}')

def sxor(m,b):
	res = bytearray()
	if(len(m) == len(b)):		
		for x,y in zip(m,b):
			res.append(x^y)
	else:
		for char in m:
			res.append(char^b[0])
	return res

def padGen():
	a1,a2,a3,a4 = (os.urandom(len(flag)),os.urandom(len(flag)),os.urandom(len(flag)),os.urandom(len(flag)))
	RandByte = bytearray(ascii_lowercase[randint(0,len(ascii_lowercase)-1)].encode())
	b1 = sxor(sxor(sxor(a1,a2),a3),a4)
	b2 = sxor(sxor(a4,a3),a2)
	b3 = sxor(a3,a1)
	print(f'Hint 1: a1 ⊕ a2 ⊕ a3 ⊕ a4 = {b1.hex()}')
	print(f'Hint 2: a2 ⊕ a3 ⊕ a4 = {b2.hex()}')
	print(f'Hint 3: a1 ⊕ a3 = {b3.hex()}')
	return sxor(a3,RandByte)

print(f'Ciphertext: flag ⊕ a3 ⊕ RandByte = {sxor(flag,padGen()).hex()}')
