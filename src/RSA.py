# Função para calcular a potência modular
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Função Miller-Rabin para teste de primalidade
def miller_rabin(n, k):
    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = (2 + n - 3) % (n - 1) + 2  # Simula um número aleatório entre 2 e n-2
        x = mod_exp(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Função para calcular o máximo divisor comum (GCD)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Função para calcular o inverso modular usando o algoritmo de Euclides estendido
def modular_inversion(e, max_value):
    if e == 0:
        return (max_value, 0, 1)
    else:
        a, b, c = modular_inversion(max_value % e, e)
        return (a, c - (max_value // e) * b, b)

# Função para gerar um número pseudo-aleatório de 'bits' bits
def pseudo_randbits(bits):
    return int('1' + '0' * (bits - 1), 2)

# Função para gerar 'k' primos de 'key_length' bits
def generate_keys(k=2, key_length=1024):
    keys = []
    for _ in range(k):
        found = False
        p = pseudo_randbits(key_length)
        while not found:
            if miller_rabin(p, 40) and p not in keys:
                found = True
                keys.append(p)
            else:
                p = pseudo_randbits(key_length)
    return keys

# Função para gerar 'e' tal que gcd(e, phi) == 1
def generate_e(phi):
    e = 3  # Valor inicial arbitrário (diferente de 1)
    while gcd(phi, e) != 1:
        e += 2  # Incremento por 2 para garantir que 'e' seja ímpar
    return e

# Função para gerar o inverso multiplicativo de 'e'
def generate_d(e, max_value):
    return modular_inversion(e, max_value)[1] % max_value

# Função para gerar chaves públicas e privadas dadas 'p' e 'q'
def generate_pub_priv_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = generate_e(phi)
    d = generate_d(e, phi)
    public_key = (n, e)
    private_key = (n, d)
    return (public_key, private_key)