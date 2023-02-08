import os
import base64
import struct
from itertools import zip_longest
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor, strxor_c
LINES = open("19.txt", "r").read().splitlines()
#KEY = os.urandom(16)
KEY = b'\xa3\xc9\xe7\xedmZU\x1e\xac\x15\xe2\xaf\xb4$\xa9{'

LETTERS_FREQUENCY = {
    " ": 19.18182,
    "e": 11.1607,
    "a": 8.4966,
    "r": 7.5808,
    "i": 7.5448,
    "o": 7.1635,
    "t": 6.9509,
    "n": 6.6544,
    "s": 5.7351,
    "l": 5.4893,
    "c": 4.5388,
    "u": 3.6308,
    "d": 3.3844,
    "p": 3.1671,
    "m": 3.0129,
    "h": 3.0034,
    "g": 2.4705,
    "b": 2.0720,
    "f": 1.8121,
    "y": 1.7779,
    "w": 1.2899,
    "k": 1.1016,
    "v": 1.0074,
    "x": 0.2902,
    "z": 0.2722,
    "j": 0.1965,
    "q": 0.1962,
}

def score(s):
    score = 0
    for t in s:
        c = chr(t).lower()
        if c in LETTERS_FREQUENCY:
            score += LETTERS_FREQUENCY[c]
    return score

def find_by_frequency(text):
    def key(k):
        return score(k[1])
    return max(((i, strxor_c(text,i)) for i in range(0,256)), key=key)

class CTR:
    def __init__(self, ECB, nonce):
        self._ECB = ECB
        self._nonce = nonce
        self._blocksize = 16
        self._keybytes = b''
        self._blockcount = 0

    def encrypt(self, plaintext):
        # Work around strxor() not handling zero-length strings
        # gracefully.
        if len(plaintext) == 0:
            return b''

        keystream = self._keybytes
        while len(keystream) < len(plaintext):
            keyblock = self._ECB.encrypt(struct.pack('<QQ', self._nonce, self._blockcount))
            keystream += keyblock
            self._blockcount += 1

        if len(keystream) > len(plaintext):
            self._keybytes = keystream[len(plaintext):]
            keystream = keystream[:len(plaintext)]
        print(f"[DEBUG] {keystream}")
        return strxor(plaintext, keystream)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)

if __name__ == '__main__':
    ciphertexts = []
    for line in LINES:
        cipher = CTR(AES.new(KEY, AES.MODE_ECB), 0)
        plaintext = base64.b64decode(line)
        ciphertext = cipher.encrypt(plaintext)
        ciphertexts.append(ciphertext)
    chars = [(list(i).remove(None) if (None in list(i)) else list(i)) for i in zip_longest(*ciphertexts)]
    keys = []
    for char in chars:
        if char:
            keys.append(find_by_frequency(bytes(char))[1])
    print([bytes(i) for i in zip_longest(*keys)])
