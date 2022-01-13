import secrets
import datetime

from helpfunctions import concat, generate_two_large_safe_primes, hash_to_prime, hash_to_length, bezoute_coefficients,\
    mul_inv, xgcd

RSA_KEY_SIZE = 256  # RSA key size for 128 bits of security (modulu size)
RSA_PRIME_SIZE = int(RSA_KEY_SIZE / 2)
ACCUMULATED_PRIME_SIZE = 128  # taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1


def test_trapdoor_setup():
    p, q = generate_two_large_safe_primes(128)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = mul_inv(e,phi)
    return p, q, n, e, d


def acc_setup():
    # draw strong primes p,q
    p, q = generate_two_large_safe_primes(RSA_PRIME_SIZE)
    n = p*q
    # draw random number within range of [0,n-1]
    # A0 = secrets.randbelow(n)E
    A0 = 4
    # print(p)
    # print(q)
    # print(n)
    return p, q, n, A0


def add(A, S, x, n):
    if x in S.keys():
        return A
    else:
        hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
        A = pow(A, hash_prime, n)
        S[x] = nonce
        return A


def batch_add(A_pre_add, S, x_list, n):
    A_post_add = A_pre_add
    for x in x_list:
        if x not in S.keys():
            # print(x)
            hash_prime, nonce = hash_to_prime(x, ACCUMULATED_PRIME_SIZE)
            # print(hash_prime)
            S[x] = nonce
            A_post_add = pow(A_post_add, hash_prime, n)
        else:
            print(x)
    return A_post_add


def prove_membership(A0, S, x, n):
    if x not in S.keys():
        return None
    else:
        # A = A0      
        for element in S.keys():
            if element != x:
                nonce = S[element]
                product = hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0]
                # A = pow(A, hash_to_prime(element, ACCUMULATED_PRIME_SIZE, nonce)[0], n)

        A = pow(A0, product, n)
        return A