import {
    BinaryLike,
    createCipheriv,
    createDecipheriv,
    createHmac,
    pbkdf2Sync,
    randomBytes,
    timingSafeEqual
} from 'crypto'

export class AES256CBC {
    public encrypt(text: string, masterkey: BinaryLike) {
        const iv = randomBytes(16)
        const salt = randomBytes(64)

        const key = pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')
        const cipher = createCipheriv('aes-256-cbc', key, iv)

        let encrypted = Buffer.concat([cipher.update(text, 'utf-8'), cipher.final()])

        const hmac = createHmac('sha256', key)
        hmac.update(encrypted)

        return Buffer.concat([salt, iv, encrypted, hmac.digest()]).toString('base64')
    }

    public decrypt(encdata: string, masterkey: BinaryLike) {
        const bData = Buffer.from(encdata, 'base64')

        const salt = bData.slice(0, 64)
        const iv = bData.slice(64, 80)
        const encrypted = bData.slice(80, -32)
        const receivedHmac = bData.slice(-32)

        const key = pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')

        const hmac = createHmac('sha256', key)
        hmac.update(encrypted)

        const calculatedHmac = hmac.digest()

        if (!timingSafeEqual(calculatedHmac, receivedHmac)) {
            throw new Error('HMAC verification failed')
        }

        const decipher = createDecipheriv('aes-256-cbc', key, iv)

        const decrypted = decipher.update(encrypted) + decipher.final('utf-8')

        return decrypted
    }
}
