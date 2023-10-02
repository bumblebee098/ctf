# Rivest, Shamir and Adleman Writeup

### Source code 

```py
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
```

### Solution
We can see that the flag is split into two parts.

First let's do some setup for extracting the keys and decode funtion:
```py
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

def getKeys(file_name):
    with open(file_name, "rb") as f:
        key = RSA.import_key(f.read())

    return key.e, key.n

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
```

#### Part 1
The first thing we see is that $N2$ is generated using two primes $a$ and $b$ that are close. 

In general when using two close primes $p$ and $q$ in RSA key generation ruins the security. If $p - q < n^\frac{1}{4}$, we can use Fermat's factoring algorithm to factor $n$ efficently.

If $n = pq$ is factorization of $n$, then

$$n = pq = (\frac{p+q}{2})^2 - (\frac{q-p}{2})^2 = x^2 - y^2$$

where $x = \frac{p+q}{2}$ and $y = \frac{q-p}{2}$.

From here we can clearly see, that:

$$n = (x+y)(x-y)$$

We can recover our $a$ and $b$ factors with Fermat's algortihm.
```py
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
```
And then decode first part of our flag: `Amazon{RSA_15`.

#### Part 2

Looking at this line of code
```py
max_prime = p % q if p > q else q % p
```
we can see that it is just $maxprime = |(p-q)|$.

We now also know the values of $a$ and $f1$. The idea is to loop from $a$ to previous prime of $a$ to get the difference $|(p-q)|$. From there we can easily factor $N1$.

Next step is based on [this problem](https://math.stackexchange.com/questions/335177/twin-prime-pair-helping-to-factor-large-numbers-quicker).

We have $p-q = m$ and we know $n=pq$. Note that for any numbers $p$ and $q$ holds this equation:

$$(p+q)^2 = (p-q)^2 + 4pq$$

We know how to calculate the right-hand side, so we can quickly calculate $p+q$. And since we know that $p-q=m$, finding $p$ and $q$ is cheap.

We can expand our equation:

$$
\begin{align} (p+q)^2 = (p-q)^2 + 4pq
(p+q)^2 = m^2 + 4n
p+q = \sqrt{m^2+4n}
(p+q)+(p-q) = \sqrt{m^2+4n}+m
2p = \sqrt{m^2+4n}+m
p = \frac{\sqrt{m^2+4n}+m}{2}
\end{align}$$

And write the code:
```py
p, q = 0, 0
for x in range(h, a):
    diff = x - bytes_to_long(flag_1)
    s = sqrt(diff**2 + (4*n1))
    if s == int(s):
        p = int((s + diff ) // 2)
        q = n1 // p
        if p*q == n1:
            break
```

Then decode the second part of our flag: `_EveryWh3r3}`

`Amazon{RSA_15_EveryWh3r3}`
