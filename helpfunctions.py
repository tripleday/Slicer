# Primality Testing with the Rabin-Miller Algorithm
# http://inventwithpython.com/hacking (BSD Licensed)

import random
import hashlib
import secrets
import math
from Crypto.Cipher import AES
import base64
import hmac
import sys


def rabin_miller(num):
    # Returns True if num is a prime number.
    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t to count how many times we halve s)
        s = s // 2
        t += 1

    # for trials in range(5): # try to falsify num's primality 5 times
    #     a = random.randrange(2, num - 1)
    for a in [2 ,7, 61]:
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def is_prime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabin_miller().

    if (num < 2):
        return False # 0, 1, and negative numbers are not prime

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabin_miller(), but unlike rabin_miller() is not guaranteed to
    # prove that a number is prime.
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # If all else fails, call rabin_miller() to determine if num is a prime.
    return rabin_miller(num)


def generate_large_prime(num_of_bits):
    while True:
        num = secrets.randbelow(pow(2, num_of_bits))
        if is_prime(num):
            return num


def generate_two_large_safe_primes(num_of_bits):
    p = generate_large_prime(num_of_bits)
    while not is_prime((p-1)//2):
        p = generate_large_prime(num_of_bits)
        # print(p)
    q = generate_large_prime(num_of_bits)
    while (not is_prime((q-1)//2) or p==q):
        q = generate_large_prime(num_of_bits)
        # print(q)

    # print(is_prime((p-1)//2))
    # print(is_prime((q-1)//2))
    return p,q


def hash_to_prime(x, num_of_bits=128, nonce=0):
    while True:
        num = hash_to_length(x + nonce, num_of_bits)
        if is_prime(num):
            return num, nonce
        nonce = nonce + 1


def hash_to_length(x, num_of_bits=128):
    pseudo_random_hex_string = ""
    num_of_blocks = math.ceil(num_of_bits / 256)
    for i in range(0, num_of_blocks):
        pseudo_random_hex_string += hashlib.sha256(str(x + i).encode()).hexdigest()

    if num_of_bits % 256 > 0:
        pseudo_random_hex_string = pseudo_random_hex_string[int((num_of_bits % 256)/4):]  # we do assume divisible by 4
    return int(pseudo_random_hex_string, 16)


# input string, output 128-bit int
def string_to_number(s):
    return int(hashlib.sha256(s.encode()).hexdigest()[32:], 16)


# input string, output 128-bit prime
def string_to_prime(s):
    num = string_to_number(s)
    while True:
        if is_prime(num):
            return num
        num = num + 1


# input string list, output 128-bit int
def hashset(l, q):
    h = 1
    for b in l:
        h = (h*string_to_number(b)) % q
    return h


# input original hash, string list, output 128-bit int
def hashsetAdd(h, l, q):
    for b in l:
        h = (h*string_to_number(b)) % q
    return h


def xgcd(b, a):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while a != 0:
        q, b, a = b // a, a, b % a
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mul_inv(b, n):
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n


def concat(*arg):
    res = ""
    for i in range(len(arg)):
        res += str(arg[i]%(1<<128))
    return int(hashlib.sha256(res.encode()).hexdigest(),16)    
    # return int(res)


def bezoute_coefficients(a, b):
    o = xgcd(a, b)
    return o[1], o[2]


def list_product(p):
    if len(p)&(len(p)-1)==0:
        t=len(p).bit_length()-1
    else:
        t=len(p).bit_length()

    for i in range((1<<t)-len(p)):
        p.append(1)
    while len(p)!=1:
        q=[]
        for i in range(len(p)//2):
            q.append(p[2*i]*p[2*i+1])
        # size = 0
        # for e in q:
        #         size += sys.getsizeof(e)
        # print(size)
        p=q
    return p[0]


def xor_hexstr(stra, strb): # return 32 long hex str
    # hexa = stra.hex()
    # hexb = strb.hex()
    resultInt = int(stra,16) ^ int(strb,16)
    return hex(resultInt)[2:].zfill(32) # '0x'


def hmac128(key, text): # input two str, return 128-bit hex string
    return hmac.digest(str.encode(key), str.encode(text), digest='MD5').hex() # 使用了优化的 C 或内联实现，对放入内存的消息能处理得更快

def hmac128_low(key, text): # input two str, return 128-bit hex string
    h = hmac.new(str.encode(key), str.encode(text), digestmod='MD5')
    return h.hexdigest()


def hmac256(key, text): # input two str, return 256-bit hex string
    h = hmac.new(str.encode(key), str.encode(text), digestmod='SHA256')
    return h.hexdigest()


# AES-128
def aes_encode(key, text): # input two str, return hex string
    # 秘钥
    # key = '123456'
    # 待加密文本
    # text = 'abc123def456'
    # 初始化加密器
    aes = AES.new(pad_to_16(key), AES.MODE_ECB)
    #先进行aes加密
    encrypt_aes = aes.encrypt(pad_to_16(text))
    #用base64转成字符串形式
    # encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
    # print(encrypted_text)
    return encrypt_aes.hex()


def aes_decode(key, ciphertext): # input two str, return hex string
    # 秘钥
    # key = '123456'
    # 密文
    # ciphertext = 'qR/TQk4INsWeXdMSbCDDdA=='
    # 初始化加密器
    aes = AES.new(pad_to_16(key), AES.MODE_ECB)
    # #优先逆向解密base64成bytes
    # base64_decrypted = base64.decodebytes(ciphertext.encode(encoding='utf-8'))
    # #执行解密密并转码返回str
    # decrypted_text = str(aes.decrypt(base64_decrypted),encoding='utf-8').strip('\0') 
    # print(decrypted_text)
    decrypted_text = aes.decrypt(bytes.fromhex(ciphertext))
    return str(decrypted_text,encoding='utf-8').strip('\0') 
    

def pad_to_16(value):
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)  # 返回bytes


def get_size(obj, seen=None):
    """Recursively finds size of objects"""
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    # Important mark as seen *before* entering recursion to gracefully handle
    # self-referential objects
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_size(v, seen) for v in obj.values()])
        size += sum([get_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_size(i, seen) for i in obj])
    return size