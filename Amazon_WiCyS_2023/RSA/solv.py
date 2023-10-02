from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
import gmpy2
from math import sqrt
from sympy import *

def getKeys(file_name):
    with open(file_name, "rb") as f:
        key = RSA.import_key(f.read())

    return key.e, key.n

def FermatFactor(n: int, max_steps: int):
    if n % 2 == 0:
        return 2, n // 2

    a = gmpy2.isqrt(n)

    if a * a == n:
        return a, a

    a += 1
    b2 = a * a - n

    for _ in range(max_steps):
        if gmpy2.is_square(b2):
            return a - gmpy2.isqrt(b2), a + gmpy2.isqrt(b2)

        b2 += a
        a += 1
        b2 += a
    return None

def decode(p, q, n, ct):
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    pt = pow(ct, d, n)
    return long_to_bytes(pt)


_, n1 = getKeys("key1.pem")
_, n2 = getKeys("key2.pem")
e = 65539
ct1 = int(open("cipher1.txt").read().strip())
ct2 = int(open("cipher2.txt").read().strip())

# part 1
a, b = FermatFactor(n2, 30)
assert a*b == n2

flag_1 = decode(a, b, n2, ct2)

# part 2
h = prevprime(a)

p, q = 0, 0
for x in range(h, a):
    diff = x - bytes_to_long(flag_1)
    s = sqrt(diff**2 + (4*n1))
    if s == int(s):
        p = int((s + diff ) // 2)
        q = n1 // p
        if p*q == n1:
            break

assert p*q == n1
flag_2 = decode(p, q, n1, ct1)

print(flag_1 + flag_2)  # Amazon{RSA_15_EveryWh3r3}