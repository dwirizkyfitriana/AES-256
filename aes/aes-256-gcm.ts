import { BinaryLike, createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'crypto'

export class AES256GCM {
    public encrypt(text: string, masterkey: BinaryLike) {
        const iv = randomBytes(16)
        const salt = randomBytes(64)

        const key = pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')

        const cipher = createCipheriv('aes-256-gcm', key, iv)

        const encrypted = Buffer.concat([cipher.update(text, 'utf-8'), cipher.final()])

        const tag = cipher.getAuthTag()

        return Buffer.concat([salt, iv, tag, encrypted]).toString('base64')
    }

    public decrypt(encdata: string, masterkey: BinaryLike) {
        const bData = Buffer.from(encdata, 'base64')

        const salt = bData.slice(0, 64)
        const iv = bData.slice(64, 80)
        const tag = bData.slice(80, 96)
        const encrypted = bData.slice(96)

        const key = pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512')

        const decipher = createDecipheriv('aes-256-gcm', key, iv)
        decipher.setAuthTag(tag)

        const decrypted = decipher.update(encrypted) + decipher.final('utf8')

        return decrypted
    }
}
