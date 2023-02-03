
import os
import base64
import string
from collections import Counter
from itertools import accumulate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

s = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
def encrypt(data):
    data = data + base64.b64decode(s)
    cipher = AES.new(os.urandom(16), AES.MODE_ECB)
    encryption = cipher.encrypt(pad(data, 16))
    return encryption

def break_cipher_block_size():
    def _break_cipher_block_size(l):
        return len(encrypt(b'\x00'*l))
    l = list(map(_break_cipher_block_size,range(128)))
    #print(l)
    return max(Counter(l).items(),key=lambda x:x[1])[1]

def break_cipher():
    block_size = break_cipher_block_size()
    padding_size = 6 # 从break_cipher_block_size中的列表可得知
    def _break_cipher(plaintext, b):
        last_block_index = -((b // block_size) + 1)
        for s in string.printable:
            _plaintext = s + plaintext
            padding = pad(_plaintext.encode()[:block_size], block_size) + b'A' * (padding_size + b)
            print(padding)
            print(b)
            e = encrypt(padding)
            blocks = [e[i:i+block_size] for i in range(0, len(e),block_size)]
            if blocks[0] == blocks[last_block_index]:
                return _plaintext
        raise Exception
    print(list(accumulate(range(1,256), _break_cipher, initial='')))
break_cipher()