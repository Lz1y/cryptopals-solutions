from Crypto.Util.strxor import strxor_c
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

def calc_hanmming_distance(s1, s2):
    return sum([bin(s1[i] ^ s2[i]).count('1') for i in range(len(s1))])

assert calc_hanmming_distance(b"this is a test", b"wokka wokka!!!") == 37

import base64 as b64
import itertools
CONTENT = b64.b64decode(open("6.txt", "r").read().replace("\n",""))

def normalized_hanming_distance(blocks):
    pairs = list(itertools.combinations(blocks[:4], 2))
    scores = [calc_hanmming_distance(p[0], p[1])/float(len(blocks[0])) for p in pairs]
    return sum(scores) / len(scores)

def break_xorkey_len(k):
    blocks = [CONTENT[i:i+k] for i in range(0, len(CONTENT), k)]
    return normalized_hanming_distance(blocks)

def break_xor_key(l):
    blocks = [CONTENT[i:i+l] for i in range(0, len(CONTENT), l)]
    transposedBlocks = list(itertools.zip_longest(*blocks, fillvalue=0))
    key = [find_by_frequency(bytes(x))[0] for x in transposedBlocks]
    return bytes(key)

def xor_encode(text, key):
    for idx, t in enumerate(text):
        yield t ^ key[idx % len(key)]

l = min(range(2,41), key=break_xorkey_len)
k = break_xor_key(l)
print(k)
print(bytes(x for x in xor_encode(CONTENT, k)))
