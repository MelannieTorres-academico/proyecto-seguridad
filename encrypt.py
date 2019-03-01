
# RC4
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/arc4.html

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Random import get_random_bytes
from time import time


def arc4(key, message):
    nonce = get_random_bytes(16)
    tempkey = SHA.new(key+nonce).digest()
    cipher = ARC4.new(tempkey)
    msg = nonce + cipher.encrypt(message)
    return msg


#des
#https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.DES-module.html

# from Crypto.Cipher import DES3
# from Crypto import Random
#
# key = b'Sixteen byte key'
# iv = Random.new().read(DES3.block_size)
# cipher = DES3.new(key, DES3.MODE_OFB, iv)
# plaintext = b'sona si latine loqueris '
# msg = iv + cipher.encrypt(plaintext)
# print(msg)


#aes

def main():
    keys_tests = ['01 02 03 04 05', '01 02 03 04 05 06 07']

    for key_string in keys_tests:
        test_arc4(key_string)
        tests_aes(key_string)





# 40 bites key
def test_arc4(key_string):
    key = bytearray.fromhex(key_string)
    start_time = time()
    for i in range(1000):
        result = arc4(key,  b'0')
    #end time
    elapsed_time = (time() - start_time)/1000
    print("Elapsed time: %.10f seconds." % elapsed_time)




if __name__ == "__main__":
    main()
