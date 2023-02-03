from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from itertools import accumulate
import binascii
import base64
CONTENT = base64.b64decode(open("10.txt", "r").read())

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
            plaintext = strxor(prev_ciphertext, intermediary)
            return (plaintext, _next)

        blocks = self.split_as_blocks(passphrase)
        plaintext = [x[0] for x in accumulate(blocks, func=_decrypt, initial=(0, self.IV))]
        return b''.join(plaintext[1:-1] + self.unpadding(plaintext[-1]))
        
cipher = CBC(AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB), b"\x00" * 16)
deadbeef = cipher.encrypt(b"deadbeefdeadbeefa")
print(deadbeef)
print(cipher.decrypt(binascii.unhexlify(deadbeef)))
print(cipher.decrypt(CONTENT))