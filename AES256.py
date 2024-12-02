import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import padding


class AES256:
    def __init__(self):
        
        #self.iv = os.urandom(16)
        #self.key = os.urandom(32)
        self.key = b'\x00' * 32 
        self.iv = b'\x00' * 16

    def encrypt_AES256(self,message):
        print(self.key)
        print(self.iv)
        message = message.encode('utf-8')
        
       
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message)
        padded_data += padder.finalize()
        message = padded_data

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)) 
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        return ciphertext

    def decrypt_AES(self,ciphertext):
        print(self.key)
        print(self.iv)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(plaintext)
        message = data + unpadder.finalize()

        return message.decode('utf-8')
    