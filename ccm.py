from Crypto.Cipher import AES
import binascii, os
encoding = 'ISO-8859-1'

def encrypt_CCM(msg: str, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_CCM)
    ciphered, authTag = aesCipher.encrypt_and_digest(msg.encode(encoding))
    return ciphered, aesCipher.nonce, authTag


def decrypt_CCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_CCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext.decode(encoding)

def randomKey():
    return os.urandom(16)

