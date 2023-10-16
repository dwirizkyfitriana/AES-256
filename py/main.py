import aes_256_gcm
import aes_256_cbc

# _crypto = aes_256_gcm.AES256GCM()
_crypto = aes_256_cbc.AES256CBC()

text = "aku tampan"
masterKey = "123"

encrypted = _crypto.encrypt(text, masterKey)
decrypted = _crypto.decrypt(encrypted, masterKey)

print(text)
print(encrypted)
print(decrypted)
