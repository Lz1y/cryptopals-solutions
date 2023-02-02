import base64 as b64
from Crypto.Cipher import AES
CONTENT = b64.b64decode(open("7.txt", "r").read().replace("\n",""))

print(CONTENT)
cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
print(cipher.decrypt(CONTENT))