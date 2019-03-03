from time import time
repetitions = 10000

#rsa pss
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA
from Crypto.Random import random

# RSA pss
# https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html
# Signs using RSA PSS
# Params a public key and a bytes message
# Returns the signature in bytes
def rsa_pss(key, message):
    h = SHA256.new(message)
    sig = PKCS1_PSS.new(key).sign(h)
    return h, sig

# Verifies that the signature is valid
# params h and signature sig and key
# returns if it's valid or not
def rsa_pss_verifying(h, key, sig):
    return PKCS1_PSS.new(key).verify(h, sig)

# https://www.dlitz.net/software/pycrypto/api/current/Crypto.PublicKey.DSA-module.html
# Signs using DSA
# Params a public key and a bytes message
# Returns the signature in bytes
def dsa(key, message):
    h = SHA.new(message).digest()
    k = random.StrongRandom().randint(1,key.q-1)
    sig = key.sign(h,k)
    verify_dsa(h, key, sig)
    return h, sig

# Verifies that the signature is valid
# params h and signature sig and key
# returns if it's valid or not
def verify_dsa(h, key, sig):
    return key.verify(h, sig)

# Generates a public and a private key
# Params int containing the size of bits
# Returns the message encrypted in bits
def generateKey(bits):
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    return private_key, public_key

def main():
    messages_tests = ['01 02 03 04 05', '01 02 03 04 05 06 07',
    '01 02 03 04 05 06 07 08', '01 02 03 04 05 06 07 08 09 0a',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20']

    messages_sizes = [40, 56, 64, 80, 128, 192, 256]

    print('RSA PSS Signing')
    for i in range(0, len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        h, key, sig = test_rsa_pss(messages_tests[i])

    print('RSA PSS Verifying')
    for i in range(0, len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_verify_rsa(h, key, sig)

    print('DSA Signing')
    for i in range(0, len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        h, key, sig = test_dsa(messages_tests[i])

    print('DSA Verifying')
    for i in range(0, len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_verifydsa(h, key, sig)

# Testing
def test_rsa_pss(message):
    message = bytes.fromhex(message)
    private, key = generateKey(1024)
    key = RSA.importKey(private)
    h = []
    sig = []
    start_time = time()
    for i in range(repetitions):
        _h, _sig = rsa_pss(key, message)
        h.append(_h)
        sig.append(_sig)
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)
    return h, key, sig

def test_verify_rsa(h, key, sig):
    start_time = time()
    for i in range(repetitions):
        rsa_pss_verifying(h[i], key, sig[i])
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

def test_dsa(message):
    message = bytes.fromhex(message)
    key = DSA.generate(1024)       # https://pycryptodome.readthedocs.io/en/latest/src/public_key/dsa.html
    h = []
    sig = []
    start_time = time()
    for i in range(repetitions):
        _h, _sig = dsa(key, message)
        h.append(_h)
        sig.append(_sig)
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)
    return h, key, sig

def test_verifydsa(h, key, sig):
    start_time = time()
    for i in range(repetitions):
        verify_dsa(h[i], key, sig[i])
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

if __name__ == "__main__":
    main()
