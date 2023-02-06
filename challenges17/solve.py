# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
import os
import base64
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from itertools import accumulate
import random
KEY = os.urandom(16)

def validate_pad(s):
    pad_size = s[-1]
    if s[-pad_size:] != (pad_size.to_bytes(1,'little') * pad_size):
        raise Exception
    return True

def encrypt():
    iv = b'0'*16
    s = open("17.txt").read().splitlines()
    s = [pad(base64.b64decode(i), 16) for i in s]
    plaintext = s[random.randrange(len(s))]
    
    cipher = AES.new(key=KEY, mode=AES.MODE_CBC, IV = iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, iv

def decrypt_and_validate(iv, ciphertext):
    cipher = AES.new(key=KEY, mode=AES.MODE_CBC, IV = iv)
    plaintext = cipher.decrypt(ciphertext)
    print(f"[DEBUG] decrypt_and_validate.plaintext: {plaintext}")
    return validate_pad(plaintext)

def exploit():
    def _explit(block):
        def break_padding(prev, index):
            print(f"[DEBUG] exploit._explit.break_padding.index: {index}")
            print(f"[DEBUG] exploit._explit.break_padding.prev: {prev}")
            padding_size = index
            prev = strxor(prev, (padding_size).to_bytes(1,'little') * len(prev))

            iv = bytearray(b'0' * (16 - len(prev)) + prev)
            for i in range(256):
                byte = i.to_bytes(1,'little')
                iv[-padding_size] = i
                try:
                    decrypt_and_validate(iv, block)
                except:
                    continue
                ret = byte + prev
                print(f"[DEBUG] exploit._explit.break_padding.byte: {byte}")
                print(f"[DEBUG] exploit._explit.break_padding.ret: {ret}")
                ret = strxor(ret, padding_size.to_bytes(1,'little') * padding_size)
                return ret
        return list(accumulate(range(1, 17), break_padding, initial=b''))[-1]
    ciphertext, iv = encrypt()
    ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    intermediary_blocks = [_explit(block) for block in ciphertext_blocks]
    ciphertext_blocks.insert(0, iv)
    plaintest_blocks = []
    for idx in range(len(intermediary_blocks)):
        plaintest_blocks.append(strxor(intermediary_blocks[idx], ciphertext_blocks[idx]))
    return b''.join(plaintest_blocks)

print(exploit())