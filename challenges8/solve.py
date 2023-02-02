import binascii
from Crypto.Cipher import AES
from collections import Counter
LINES = open("8.txt", "r").read().splitlines()

def finder_wrapper():
    def _inner(i):
        index = i[0]
        line = i[1]
        c = binascii.unhexlify(line)
        blocks = [c[x:x+16] for x in range(0, len(c), 16)]
        return Counter(blocks).most_common()[0][1]
    return max(enumerate(LINES), key=_inner)
    
if __name__ == '__main__':
    print(finder_wrapper())