from time import time
repetitions = 100

#rsa pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA

# RSA pss
# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html
# Signs using RSA PSS
# Params a public key and a bytes message
# Returns the signature in bytes
def rsa_pss(key, message):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.DSA-module.html
# Signs using DSA
# Params a public key and a bytes message
# Returns the signature in bytes
def dsa(key, message):
    h = SHA.new(message).digest()
    k = random.StrongRandom().randint(1,key.q-1)
    sig = key.sign(h,k)
    return sig

def main():
    test_rsa_pss()
    test_dsa()

def test_rsa_pss():
    start_time = time()
    message = b'You can attack now!'
    key = RSA.importKey(open('public_key.pem').read())
    for i in range(repetitions):
        rsa_pss(key, message)
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

def test_dsa():
    start_time = time()
    message = "Hello".encode('utf-8')
    key = DSA.generate(1024)
    for i in range(repetitions):
        dsa(key, message)
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

if __name__ == "__main__":
    main()
