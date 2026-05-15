from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class SecureSession:

    def __init__(self, key, aad=b""):
        self.aesgcm = AESGCM(key)
        self.aad = aad

    def encrypt(self, plaintext):
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, self.aad)
        return nonce + ciphertext

    def decrypt(self, data):
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, self.aad)
