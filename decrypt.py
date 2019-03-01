from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from time import time

repetitions = 100

# RC4
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/arc4.html

def arc4(key, message):
    nonce = get_random_bytes(16)
    tempkey = SHA.new(key+nonce).digest()
    cipher = ARC4.new(tempkey)
    msg = nonce + cipher.decrypt(message)
    return msg

#des
#https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.DES-module.html

from Crypto.Cipher import DES3
from Crypto import Random

def des(key, plaintext):
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    msg = iv + cipher.encrypt(plaintext)
    print(msg.hex())


#aes
#https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Cipher import AES
from Crypto import Random
def aes(key, plaintext):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = iv + cipher.decrypt(plaintext)
    return msg

#RSA-­OAEP
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
def rsa_oaep(key, message):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_oaep_dec(key, message):
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(message)
    return plaintext

from Crypto.PublicKey import RSA
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


    #RC4
    print('RC4 tests')
    for i in range(0, len(messages_sizes)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_arc4(messages_tests[i])

    #DES
    print('DES tests')
    for i in range(0, len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_des(messages_tests[i])

    # AES
    print('AES test')
    for i in range (len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_aes(messages_tests[i])

    #RSA-OAEP
    print('RSA-OAEP test')
    for i in range (len(messages_tests)):
        print('Message size: ', messages_sizes[i],' bits', end=' ')
        test_rsa_oaep(messages_tests[i])

def test_arc4(message):
    key = bytearray.fromhex('01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20')
    start_time = time()
    for i in range(repetitions):
        result = arc4(key,  message)
    elapsed_time = (time() - start_time)/repetitions
    print('Key size: 256 bits', end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)


def test_des(message):
    start_time = time()
    key = b'8000000000000000'
    for i in range(repetitions):
        result = arc4(key,  message)
    elapsed_time = (time() - start_time)/repetitions
    print('Key size: 64 bits', end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)


# solo un tamaño de llave, cambiar longitud de mensaje
def test_aes(message):
    key = bytes.fromhex('60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4')
    start_time = time()
    for i in range(repetitions):
        result = aes(key, message)
    elapsed_time = (time() - start_time)/repetitions
    print('Key size: 256 bits', end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

def test_rsa_oaep(message):
    start_time = time()
    message = bytes.fromhex(message)
    private, key = generateKey(1024)
    key = RSA.importKey(key)
    enc = rsa_oaep(key, message)
    for i in range(repetitions):
        result = rsa_oaep_dec(private, enc)
    elapsed_time = (time() - start_time)/repetitions
    print("Key size: 1024 bits", end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)


if __name__ == "__main__":
    main()
