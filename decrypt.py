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


def test_arc4(key_string):
    key = bytearray.fromhex(key_string)
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'Y\x81T]\xf14\n\xa4\xa1\xf7\x0f\xc7Ll\xc0\xb7m')
    elapsed_time = (time() - start_time)/1000
    print("Elapsed time: %.10f seconds." % elapsed_time)

def test_des(key):
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'95A8D72813DAA94D')
    elapsed_time = (time() - start_time)/1000
    print('Key size: 64 bits', end=' ')
    print("Elapsed time: %.10f seconds." % elapsed_time)

if __name__ == "__main__":
    main()
