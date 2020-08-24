from Crypto.Cipher import AES
import binascii, os
encoding = 'ISO-8859-1'

def encrypt_GCM(msg: str, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphered, authTag = aesCipher.encrypt_and_digest(msg.encode(encoding))
    return ciphered, aesCipher.nonce, authTag


def decrypt_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext.decode(encoding)

def randomKey():
    return os.urandom(32)  # 256-bit random encryption key

secretKey = os.urandom(32)  # 256-bit random encryption key
print("Encryption key:", binascii.hexlify(secretKey))

msg = 'Message for AES-256-GCM + Scrypt encryption'

encryptedMsg = encrypt_GCM(msg, secretKey)
print("encryptedMsg", {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'aesIV': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2])
})

decryptedMsg = decrypt_GCM(encryptedMsg, secretKey)
print("decryptedMsg", decryptedMsg)
