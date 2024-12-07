import random
def get_random_number(min_val, max_val):
    return random.randint(min_val, max_val)
def is_prime(n, k=40):  # k — количество раундов, увеличено для 1000-битных чисел
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Представим n-1 в виде 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Тестируем k раз
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)  # a^d % n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True



def addouble(a, b, m):
    a = a % m
    b = b % m
    c = 0
    while a > 0:
        if a % 2 == 1:
            c = (c + b) % m
        a //= 2
        b = (b * 2) % m
    return c

def tower(a, b, m):
    c = 1
    b = b % m
    while a > 0:
        if a % 2 == 1:
            c = addouble(c, b, m)
        a //= 2
        b = addouble(b, b, m)
    return c



def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Функция для генерации ключей RSA
def generate_rsa_keys(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 17
    while gcd(e, phi_n) != 1:
        e += 2
    d = mod_inverse(e, phi_n)
    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    return tower(e,message, n)

def decrypt(ciphertext, private_key):
    d, n = private_key
    return tower( d,ciphertext, n)
p=12
q=12
while not is_prime(p):
    p = get_random_number(100000, 200000)
while not is_prime(q):
    q = get_random_number(100000, 200000)



