import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AES256GCM:
    def encrypt(self, text, masterkey):
        iv = get_random_bytes(16)
        salt = get_random_bytes(64)

        key = hashlib.pbkdf2_hmac(
            "sha512", masterkey.encode("utf-8"), salt, 2145, dklen=32
        )

        cipher = AES.new(key, AES.MODE_GCM, iv)

        encrypted = cipher.encrypt(text.encode("utf-8"))

        tag = cipher.digest()

        encrypted_data = salt + iv + tag + encrypted

        return base64.b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encdata, masterkey):
        bData = base64.b64decode(encdata)

        salt = bData[:64]
        iv = bData[64:80]
        tag = bData[80:96]
        text = bData[96:]

        key = hashlib.pbkdf2_hmac(
            "sha512", masterkey.encode("utf-8"), salt, 2145, dklen=32
        )

        cipher = AES.new(key, AES.MODE_GCM, iv)
        cipher.update(tag)

        decrypted = cipher.decrypt(text).decode("utf-8")

        return decrypted
