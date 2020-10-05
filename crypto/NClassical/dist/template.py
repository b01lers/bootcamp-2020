# You can install these packages to help w/ solving unless you have others in mind
# i.e. python3 -m pip install {name of package}
from pwn import *
import codecs
from base64 import b64decode
from string import ascii_lowercase

HOST = ''
PORT = 0

r = remote(HOST,PORT)

def bacon(s):
    # Do this

def rot13(s):
    # And this

def atbash(s):
    # And this one

def Base64(s):
    # Lastly this one

if __name__ == '__main__':
    count = 0
    while True:     
        r.recvuntil('Method: ')
        method = r.recvuntil('\n').strip()
        r.recvuntil('Ciphertext: ')
        argument = r.recvuntil('\n').strip()

        result = globals()[method.decode()](argument.decode())  # :)

        r.recv()
        r.sendline(result.encode())
        count += 1
        if count == 1000:
            print(r.recv())
            exit(0)
    
