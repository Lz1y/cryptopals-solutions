KEY = "ICE"
PLAIN_TEXT = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
def xor_encode(text):
    for idx, t in enumerate(text):
        yield ord(t) ^ ord(KEY[idx % len(KEY)])

print(bytes(x for x in xor_encode(PLAIN_TEXT)).hex())