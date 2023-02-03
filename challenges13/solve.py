import os
from Crypto.Cipher import AES
from collections import Counter
from Crypto.Util.Padding import pad, unpad
from urllib.parse import urlencode,unquote_plus
BLOCK_SIZE = 16

KEY = os.urandom(BLOCK_SIZE)
cipher = AES.new(KEY, AES.MODE_ECB)
def profile_for(email):
    email = email.replace("&",'').replace("=",'')
    obj = {
            "email": email,
            "uid": 10,
            "role": 'user'
        }
    return unquote_plus(urlencode(obj))

def encrypt_profile(p):
    return cipher.encrypt(pad(p.encode(), BLOCK_SIZE))

def decrypt_profile(p):
    return unpad(cipher.decrypt(p), BLOCK_SIZE)

def break_cipher_block_size():
    def _break_cipher_block_size(l):
        return len(encrypt_profile(profile_for('\x00' * l)))
    l = list(map(_break_cipher_block_size,range(128)))
    offset = l.count(l[0])
    return offset, max(Counter(l).items(), key=lambda x:x[1])[1]

def break_cipher():
    plaintext = "admin"
    (offset, block_size) = break_cipher_block_size()
    blocks_number = (len(plaintext.encode()) // block_size) + 1
    # email=xxxx&uid=10&role=user
    # len(email=) => 6
    # len(user) => 4
    padding = b'0' * (block_size-6) + pad(plaintext.encode(), block_size) + b'0' * offset
    encryptions = encrypt_profile(profile_for(padding.decode()))
    encryptions_blocks = [encryptions[i:i+block_size] for i in range(0, len(encryptions), block_size)]
    encryption_plaintext = encryptions_blocks[1]
    padding = b'0' * (offset + 4)
    encryptions = encrypt_profile(profile_for(padding.decode()))
    encryptions_blocks = [encryptions[i:i+block_size] for i in range(0, len(encryptions), block_size)]
    encryptions_blocks[-1] = encryption_plaintext
    return b''.join(encryptions_blocks)

print(decrypt_profile(break_cipher()))