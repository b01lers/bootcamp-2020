from Crypto.Util import number

flag = 'flag{w3_need_7o_g0_d3ep3r}'
p = number.getPrime(512)
q = number.getPrime(512)
n = p * q
e = 3

print('n:',n)

ctext = pow(int.from_bytes(flag.encode('utf-8'),'big'),e,n)
print('ciphertext:',str(ctext))

