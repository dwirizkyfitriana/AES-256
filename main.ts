import { AES256CBC } from './aes/aes-256-cbc'
import { AESCombined } from './aes/aes-256-combined'
import { AES256GCM } from './aes/aes-256-gcm'

const text = 'halo guys'
const key = '123'

// const _crypto = new AES256GCM()
const _crypto = new AES256CBC()
// const _crypto = new AESCombined()

const encrypted = _crypto.encrypt(text, key)
const decrypted = _crypto.decrypt(encrypted, key)

console.error({ text })
console.error({ encrypted })
console.error({ decrypted })
