from Crypto.Util.number import bytes_to_long, getPrime, inverse

m = b'flag{4cce551ng_th3_subc0nsc10us}'

p = getPrime(512)
q = getPrime(512)

N = p*q
e = 0x10001
d = inverse(e,(p-1)*(q-1))

c = pow(bytes_to_long(m),e,N)

print(f'Modulus: {N}\nOne factor of N:  {p}\nPublic key: {e}\nCiphertext: {c}')

