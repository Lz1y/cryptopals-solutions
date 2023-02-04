
import os
import random
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
prefix = os.urandom(random.randint(1, 16))
key = os.urandom(16)
def encrypt(data):
    data = pad(prefix + data + base64.b64decode(s), 16)
    blocks = [data[i:i+16] for i in range(0, len(data),16)]
    cipher = AES.new(key, AES.MODE_ECB)
    encryption = cipher.encrypt(data)
    return encryption

def break_cipher_block_size():
    def _break_cipher_block_size(l):
        return len(encrypt(b'\x00'*l))
    l = list(map(_break_cipher_block_size,range(128)))
    offset = l.count(l[0])
    return offset, max(Counter(l).items(),key=lambda x:x[1])[1]

def break_prefix_size():
    prefix_padding_size = 0
    offset, block_size = break_cipher_block_size()
    plaintext = pad(b'A', block_size)
    for i in range(16):
        padding = b'0' * i + plaintext + plaintext
        e = encrypt(padding)
        blocks = [e[i:i+block_size] for i in range(0, len(e),block_size)]
        for index, block in enumerate(blocks):
            if blocks[index] == blocks[index-1]:
                prefix_padding_size = i
    return prefix_padding_size

def break_cipher():
    offset, block_size = break_cipher_block_size()
    prefix_pad_size = break_prefix_size()
    suffix_pad_size = block_size + offset - prefix_pad_size
    def _break_cipher(plaintext, b):
        last_block_index = -(b // block_size + 1)
        for s in string.printable:
            _plaintext = s + plaintext
            padding = b'\x10' * (prefix_pad_size + (block_size*2)) + pad(_plaintext.encode()[:block_size], block_size) + b'A' * (b + suffix_pad_size)
            e = encrypt(padding)
            blocks = [e[i:i+block_size] for i in range(0, len(e),block_size)]
            encryptions_index = 3
            if blocks[encryptions_index] == blocks[last_block_index]:
                return _plaintext
        raise Exception
    return list(accumulate(range(1,256), _break_cipher, initial=''))[-1]

print(break_cipher())