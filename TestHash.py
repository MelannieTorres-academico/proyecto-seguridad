#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Feb 28 19:09:38 2019

@author: martin
"""

import hashlib 
from time import time
    
def timer():
    mssg = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "A...Za...z0...9", '1234567890' * 8, 'a' * 1000000]
    #MD5
    start_time = time()
    for i in range(1000):
        
        for pos in mssg:
            hashlib.md5(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/1000
    print("\n" + "Elapsed time: %.10f seconds." % elapsed_time)
    
    #SHA1
    start_time = time()
    for i in range(1000):
        
        for pos in mssg:
            hashlib.sha1(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/1000
    print("\n" + "Elapsed time: %.10f seconds." % elapsed_time)
    
    #SHA2
    start_time = time()
    for i in range(1000):
        
        for pos in mssg:
            hashlib.sha256(pos.encode('utf-8'))
            
    elapsed_time = (time() - start_time)/1000
    print("\n" + "Elapsed time: %.10f seconds." % elapsed_time)
    

def main():
    timer()
    
    
    

if __name__ == "__main__":
    main()