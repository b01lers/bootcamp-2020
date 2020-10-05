from pwn import *
import codecs
from base64 import b64decode
from string import ascii_lowercase

HOST, PORT = "crypto.ctf.b01lers.com", 65000

r = remote(HOST,PORT) # Remote Solve

def bacon(s):
    enc = ''
    groupings = [s[idx:idx+5] for idx in range(0,len(s),5)]
    for group in groupings:
        val = int(group.replace('A','0').replace('B','1'),2)
        enc += ascii_lowercase[val]
    return enc

def rot13(s):
    return codecs.decode(s,"rot_13")

def atbash(s):
    enc = ''
    for char in s:
        idx = ascii_lowercase[::-1].index(char)
        enc += ascii_lowercase[idx]
    return enc

def Base64(s):
    return b64decode(s.encode()).decode()
    
if __name__ == '__main__':
    count = 0
    while True:     
        r.recvuntil('Method: ')
        line = r.recvuntil('\n').replace(b'\n',b'')
        r.recvuntil('Ciphertext: ')
        line2 = r.recvuntil('\n').replace(b'\n',b'')
        tmp = globals()[line.decode()](line2.decode())
        r.recv()
        r.sendline(tmp.encode())
        count += 1
        if count == 1000:
            print(r.recv())
            exit(0)
    
