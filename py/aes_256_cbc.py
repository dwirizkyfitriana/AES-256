import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC


class AES256CBC:
    def encrypt(self, text: str, masterkey: str) -> str:
        iv = get_random_bytes(16)
        salt = get_random_bytes(64)

        key = hashlib.pbkdf2_hmac(
            "sha512", masterkey.encode("utf-8"), salt, 2145, dklen=32
        )

        cipher = AES.new(key, AES.MODE_CBC, iv)

        padded_text = pad(text.encode("utf-8"), AES.block_size)
        encrypted = cipher.encrypt(padded_text)

        hmac = HMAC.new(key, encrypted, hashlib.sha256)
        hmac_digest = hmac.digest()

        encrypted_data = salt + iv + encrypted + hmac_digest

        return base64.b64encode(encrypted_data).decode("utf-8")

    def decrypt(self, encdata: str, masterkey: str) -> str:
        bData = base64.b64decode(encdata)

        salt = bData[:64]
        iv = bData[64:80]
        encrypted = bData[80:-32]
        received_hmac = bData[-32:]

        key = hashlib.pbkdf2_hmac(
            "sha512", masterkey.encode("utf-8"), salt, 2145, dklen=32
        )

        hmac = HMAC.new(key, encrypted, hashlib.sha256)
        calculated_hmac = hmac.digest()

        if calculated_hmac != received_hmac:
            raise ValueError("HMAC verification failed")

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        unpadded_text = unpad(decrypted, AES.block_size)

        return unpadded_text.decode("utf-8")
