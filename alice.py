import socket
import sys
from threading import Thread
import os
import datetime
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import cryptography
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Client:

    def __init__(self, HOST, PORT):
        
        self.key= rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
        self.name = input("Enter your name: ")
        print("Generating pair of keys...")

        with open("keys/"+self.name+"_privkey.pem","wb") as f: 
            f.write(self.key.private_bytes(
                encoding =serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm= serialization.BestAvailableEncryption(b"passphrase"),
        ))
            
        self.socket = socket.socket()    
        self.socket.connect((HOST, PORT))   
        self.talk_to_server()

    def talk_to_server(self):
        self.socket.send(self.name.encode())
        Thread(target=self.receive_message).start()
        self.send_message()

    def encrypt_AES256(self,message):
        key = os.urandom(32) #32 bytes
        iv = os.urandom(16)
        message = message.encode('utf-8')
        
        if len(message) % 16 != 0:
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(message)
            padded_data += padder.finalize()
            message = padded_data

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        return ciphertext

    def decrypt_AES(self,ciphertext):
        cipher = Cipher(algorithms.AES(), modes.CBC())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(plaintext)
        message = data + unpadder.finalize()

        return message

    def send_message(self):
        while True:
            client_input = input("") 
            client_input= self.encrypt_AES256(client_input)
            print(client_input)
            
            self.socket.send((self.name+":"+client_input.hex()).encode())

    def receive_message(self):
        while True:
            server_message = self.socket.recv(1024).decode() #decifra a mensagem mandada e validar o certificado de quem mandou a mensagem
            #server_message = self.decrypt_AES(server_message)
            if not server_message.strip():
                os._exit(0)
            print("\033[1;31;40m" + server_message + "\033[0m")


if __name__ == "__main__":
    Client('localhost', 12345)