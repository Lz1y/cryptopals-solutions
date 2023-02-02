from Crypto.Util.strxor import strxor_c
import binascii

ENCODED_TEXT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# https://mdickens.me/typing/letter_frequency.html
# https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
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

def find_by_ascii(text):
    """
    False positive.
    """
    for c in range(0, 256):
        t = strxor_c(text, c).decode('utf-8', errors='ignore')
        if t.isprintable() and t.isascii() and t:
            yield t

if __name__ == '__main__':
    print(find_by_frequency(binascii.unhexlify(ENCODED_TEXT)))
    #print([x for x in find_by_ascii(binascii.unhexlify(ENCODED_TEXT))])