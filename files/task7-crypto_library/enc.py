#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Util import Padding


cipher_hex_string = '764aa26b55a4da654df6b19e4bce00f4ed05e09346fb0e762583cb7da2ac93a2'
iv_hex_string = 'aabbccddeeff00998877665544332211'
ciphertext = bytes.fromhex(cipher_hex_string)
iv = bytes.fromhex(iv_hex_string)
data = b'This is a top secret.'
print("Length of data: {0:d}".format(len(data)))

# Encrypt
def Enc(key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext1 = cipher.encrypt(Padding.pad(data, 16))
    return ciphertext1


# Find key
found = 0
with open('englishwordlist.txt') as key_list:
    for key in key_list:
        if len(key) < 16:
            key = key.strip()  #removing trailing spaces 
            key_padded = key.ljust(16, "#") #padding with "#"   
            key_string = key_padded.encode('utf-8') #encoded string

            # encrypt using the key .. calling the Enc function
            ciphertext1 = Enc(key_string)
            # check if ciphertext matches
            if ciphertext1 == ciphertext:
                print("ciphertext given:{0}".format(ciphertext.hex()))
                print("ciphertext computed:{0}".format(ciphertext1.hex()))
                print("Key found......: ",key)
                found = 1
                break

# Incase the key is not found, print a message
if found == 0:
    print("Cannot find key for given ciphertext and plaintext....")

