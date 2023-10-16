import { BinaryLike } from 'crypto'
import { AES256GCM } from './aes-256-gcm'
import { AES256CBC } from './aes-256-cbc'

export class AESCombined {
    private gcm: AES256GCM
    private cbc: AES256CBC

    constructor() {
        this.gcm = new AES256GCM()
        this.cbc = new AES256CBC()
    }

    public encrypt(text: string, masterkey: BinaryLike) {
        const cbcEncrypted = this.cbc.encrypt(text, masterkey)

        return this.gcm.encrypt(cbcEncrypted, masterkey)
    }

    public decrypt(encdata: string, masterkey: BinaryLike) {
        const gcmDecrypted = this.gcm.decrypt(encdata, masterkey)

        return this.cbc.decrypt(gcmDecrypted, masterkey)
    }
}
