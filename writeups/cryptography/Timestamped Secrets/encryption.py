from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

hint = 1770242637
ct = bytes.fromhex("030ea2b59ea3cad39da9dfff761acc2598161c602243e2b0e9e571cee8285b87")

for ts in range(hint - 10000, hint + 10001):
    key = sha256(str(ts).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
        if pt.startswith("picoCTF{") and pt.endswith("}"):
            print("timestamp =", ts)
            print("flag =", pt)
            break
    except:
        pass