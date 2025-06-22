import { IntegrationBase } from "@budibase/types"
import * as crypto from "crypto";
import * as util from "util";

class CryptoIntegration implements IntegrationBase {
    async read({ source, extra: { encoding } }: { source: string, extra: { encoding: BufferEncoding } }) {
      return Buffer.from(source).toString(encoding);
    }

    async hash({ source, extra: { algorithm, encoding } }: { source: string, extra: { algorithm: string, encoding: crypto.BinaryToTextEncoding } }) {
        const hash = crypto.createHash(algorithm);

        hash.update(source);

        return hash.digest(encoding);
    }

    async encrypt({ source, privateKey, extra: { algorithm, encoding } }: { source: string, privateKey: string, extra: { algorithm: string, encoding: BufferEncoding } }) {
        const iv = crypto.randomBytes(algorithm === 'blowfish' ? 8: 16);
        const cipher = crypto.createCipheriv(algorithm, Buffer.from(privateKey, 'base64'), iv);

        cipher.update(source);

        return {
            result: cipher.final(encoding),
            iv: iv.toString(encoding)
        };
    }

    async decrypt({ source, publicKey, iv, extra: { algorithm, encoding, sourceEncoding } }: { source: string, publicKey: string, iv: string, extra: { algorithm: string, encoding: BufferEncoding, sourceEncoding: BufferEncoding } }) {
        const decipher = crypto.createDecipheriv(algorithm, publicKey, Buffer.from(iv, sourceEncoding));

        decipher.update(source, sourceEncoding);

        return decipher.final(encoding);
    }

    async sign({ source, privateKey, extra: { algorithm, encoding } }: { source: string, privateKey: string, extra: { algorithm: string, encoding: crypto.BinaryToTextEncoding } }) {
        const sign = crypto.createSign(algorithm);

        sign.update(source);

        return sign.sign(privateKey, encoding);
    }

    async hmac({ source, privateKey, extra: { algorithm, encoding } }: { source: string, privateKey: string, extra: { algorithm: string, encoding: crypto.BinaryToTextEncoding } }) {
        const hmac = crypto.createHmac(algorithm, privateKey);

        hmac.update(source);

        return hmac.digest(encoding);
    }
}

export default CryptoIntegration
