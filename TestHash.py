#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Feb 28 19:09:38 2019

@author: martin
"""

import hashlib 
from time import time

def Message():
    #Declare sets 1 and 2 as messages 
    St1 = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "A...Za...z0...9", '1234567890' * 8, 'a' * 1000000]
    St2=[]
    for num in range(128):
        St2.append('0' * num) 
    message = St1 + St2
    return message
    
def timer():
    mssg = Message()
    
    #MD5
    #https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/md5/Md5-128.unverified.test-vectors
    start_time = time()
    for i in range(10000): #Numer of iterations
        for pos in mssg:
            hashlib.md5(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/10000
    print("\n" + "Elapsed time for MD5 Algorithm: %.10f seconds." % elapsed_time)
    
    #SHA1
    #https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/Sha-1-160.test-vectors
    start_time = time()
    for i in range(10000):
        
        for pos in mssg:
            hashlib.sha1(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/10000
    print("\n" + "Elapsed time for SHA-1 Algorithm: %.10f seconds." % elapsed_time)
    
    #SHA2
    #https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/Sha-2-256.unverified.test-vectors
    start_time = time()
    for i in range(10000):
        
        for pos in mssg:
            hashlib.sha256(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/10000
    print("\n" + "Elapsed time for SHA-2 Algorithm: %.10f seconds." % elapsed_time)
    

def main():
   timer()
    
    
    

if __name__ == "__main__":
    main()