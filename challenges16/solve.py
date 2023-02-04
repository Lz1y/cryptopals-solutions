import os
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii
from itertools import accumulate
from Crypto.Util.Padding import pad, unpad
# https://ctf-wiki.org/crypto/blockcipher/mode/cbc/#_8
KEY = os.urandom(16)
class CBC():
    def __init__(self, ECB, IV) -> None:
        self.ECB = ECB
        self.IV = IV
        self.BLOCK_SIZE = 16

    def split_as_blocks(self, s):
        return [s[i:i+self.BLOCK_SIZE] for i in range(0, len(s), self.BLOCK_SIZE)]

    def padding(self, s):
        pad_len = self.BLOCK_SIZE - (len(s) % self.BLOCK_SIZE)
        return s + binascii.unhexlify("{0:0{1}x}".format(pad_len,2)) * pad_len

    def unpadding(self, s):
        bytes_to_remove = s[-1]
        return [s[:-bytes_to_remove]]

    def encrypt(self, plaintext):
        def _encrypt(_prev, _next):
            intermediary = strxor(_prev, _next)
            ciphertext = self.ECB.encrypt(intermediary)
            return ciphertext

        blocks = self.split_as_blocks(self.padding(plaintext))
        ciphertext = [x.hex() for x in accumulate(blocks, func=_encrypt, initial=self.IV)]
        return ''.join(ciphertext[1:])

    def decrypt(self, passphrase):
        def _decrypt(_prev, _next):
            (_prev_plaintext, prev_ciphertext) = _prev
            intermediary = self.ECB.decrypt(_next)
            print(f"[DEBUG] decrypt.intermediary: {intermediary}")
            plaintext = strxor(prev_ciphertext, intermediary)
            return (plaintext, _next)

        blocks = self.split_as_blocks(passphrase)
        plaintext = [x[0] for x in accumulate(blocks, func=_decrypt, initial=(0, self.IV))]
        return b''.join(plaintext[1:-1] + self.unpadding(plaintext[-1]))

cipher = CBC(AES.new(key=KEY, mode=AES.MODE_ECB), b"\x00" * 16)

def process(data):
    data = data.replace(";","").replace("=","")
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    plaintext = f"{prefix}{data}{suffix}"
    ciphertext = cipher.encrypt(pad(plaintext.encode(), 16))
    return ciphertext

def parse(data):
    plaintext = cipher.decrypt(data)
    print(f"[DEBUG] parse.plaintext: {plaintext}")
    return b';admin=true;' in plaintext

plaintext = b'comment1=cooking%20MCs;userdata=a;comment2=%20like%20a%20pound%20of%20bacon'
plaintext_blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

c = process("a")
b = binascii.unhexlify(c)
ciphertext_blocks = [b[i:i+16] for i in range(0, len(b), 16)]

malicious_block = bytearray(ciphertext_blocks[0])
intermediary = strxor(ciphertext_blocks[0], plaintext_blocks[1])
malicious_block = strxor(intermediary, pad(b';admin=true;',16))
ciphertext_blocks[0] = malicious_block
malicious_ciphertext = b''.join(ciphertext_blocks)

status = parse(malicious_ciphertext)
print(status)