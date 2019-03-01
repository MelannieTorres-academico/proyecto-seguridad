from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from time import time

# RC4
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/arc4.html

def arc4(key, message):
    nonce = get_random_bytes(16)
    tempkey = SHA.new(key+nonce).digest()
    cipher = ARC4.new(tempkey)
    msg = nonce + cipher.encrypt(message)
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
from Crypto.Cipher import AES
from Crypto import Random
def aes():
    key = bytes.fromhex('60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = iv + cipher.encrypt(b'6bc1bee22e409f96e93d7e117393172a')
    return msg

def main():
    keys_tests = ['01 02 03 04 05', '01 02 03 04 05 06 07',
    '01 02 03 04 05 06 07 08', '01 02 03 04 05 06 07 08 09 0a',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18',
    '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20']

    key_sizes = [40, 56, 64, 80, 128, 192, 256]

    print('RC4 tests')
    for i in range(0, len(keys_tests)):
        print('Key size: ', key_sizes[i],' bits', end=' ')
        test_arc4(keys_tests[i])

    print('DES tests')
    test_des(b'8000000000000000')


    key_test_aes = ['2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c',
    '8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b',
    '60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4'
    ]
    key_sizes_aes = [128, 192, 256]

    print('AES test')
    for i in range (len(key_test_aes)):
        print('Key size: ', key_sizes_aes[i],' bits', end=' ')
        test_aes(key_test_aes[i])


def test_arc4(key_string):
    key = bytearray.fromhex(key_string)
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'0')
    elapsed_time = (time() - start_time)/1000
    print("Elapsed time: %.10f seconds." % elapsed_time)


def test_des(key):
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'0000000000000000')
    elapsed_time = (time() - start_time)/1000
    print('Key size: 64 bits', end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)


def test_aes(key_string):
    key = bytes.fromhex(key_string)
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'0')
    elapsed_time = (time() - start_time)/1000
    print("Elapsed time: %.10f seconds." % elapsed_time)

if __name__ == "__main__":
    main()
