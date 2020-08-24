from gcm import decrypt_GCM, encrypt_GCM, randomKey, encoding
from ccm import decrypt_CCM, encrypt_CCM, randomKey as ccmRandomKey



print("*"*10, "Ejemplo GCM", "*"*10)
msg = 'Mi mensaje encryptado con GCM'
secretKey = randomKey()
print("initial message: ", msg)
encryptedMsg = encrypt_GCM(msg, secretKey)
print("encrypted message ", encryptedMsg[0].decode(encoding))

decryptedMsg = decrypt_GCM(encryptedMsg, secretKey)
print("decrypted message", decryptedMsg)

print("*"*10, "Ejemplo CCM", "*"*10)
msg = 'Mi mensaje encryptado con CCM'
secretKey = ccmRandomKey()
print("initial message: ", msg)
encryptedMsg = encrypt_GCM(msg, secretKey)
print("encrypted message ", encryptedMsg[0].decode(encoding))

decryptedMsg = decrypt_GCM(encryptedMsg, secretKey)
print("decrypted message", decryptedMsg)