#!/usr/bin/python3
import random
import codecs
from string import ascii_letters, ascii_lowercase
from base64 import b64encode
from words import words #wordlist

flag = 'ctf{4n_313g4nt_s01ut10n_f0r_tr4cking_r341ity}' 

def rot13(s):
    return codecs.encode(s,"rot_13")

def bacon(s):
    #I!=J & U!=V Variant
    enc = ''
    for char in s:
        val = bin(ascii_lowercase.index(char))[2:].zfill(5).replace('1','B').replace('0','A')
        enc += val
    return enc

def atbash(s):
    enc = ''
    letters = ascii_lowercase[::-1]
    for char in s:
        enc += letters[ascii_lowercase.index(char)]
    return enc

def Base64(s):
   return b64encode(s.encode()).decode()

ciphers = [rot13, bacon, atbash, Base64]

for i in range(1000):
	func = ciphers[random.randint(0,len(ciphers)-1)]
	word = words[random.randint(0,len(words)-1)]
	enc = func(word)
	print(f'Method: {func.__name__}')
	print(f'Ciphertext: {enc}')
	dec = input('Input: ')
	if dec != word:
		print('Hm that doesn\'t seem quite right we must be awake.')
		exit()
print(f'We must be dreaming, here\'s your flag: {flag}')


