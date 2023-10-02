from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.PublicKey import RSA
import gmpy2

p = getPrime(1024)
q = getPrime(1024)

N1 = p * q
e = 65539

f = open('flag.txt', 'rb').read()
f1 = bytes_to_long(f[:len(f)//2])
f2 = bytes_to_long(f[len(f)//2:])

max_prime = p % q if p > q else q % p

a = gmpy2.next_prime(max_prime + f1)
b = gmpy2.next_prime(a)

for _ in range(66):
    b = gmpy2.next_prime(b)

N2 = a * b

c1 = pow(f2, e, N1)
c2 = pow(f1, e, N2)

pub1 = RSA.construct((int(N1), e))
pub2 = RSA.construct((int(N2), e))
with open("key1.pem", "wb") as f:
    f.write(pub1.exportKey("PEM"))
with open("key2.pem", "wb") as f:
    f.write(pub2.exportKey("PEM"))

with open("cipher1.txt", 'wb') as f1, open("cipher2.txt", 'wb') as f2:
    f1.write(str(c1).encode('utf-8'))
    f2.write(str(c2).encode('utf-8'))