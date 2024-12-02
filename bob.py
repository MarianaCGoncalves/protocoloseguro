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
from AES256 import *

# TODO: FALTA A VALIDAÇÃO ENTRE UTILIZADORES

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
        self.aes = AES256() 
        self.talk_to_server()

    def talk_to_server(self):
        self.socket.send(self.name.encode())
        Thread(target=self.receive_message).start()
        self.send_message()

    def send_message(self):
        while True:
            client_input = input("")
            client_input= self.aes.encrypt_AES256(client_input)
            print(client_input)
            self.socket.send((self.name+":"+client_input.hex()).encode())


#TODO: TESTAR MENSAGENS DECIFRADAS!!!!
    def receive_message(self):
        while True:
            server_message = self.socket.recv(1024).decode()
            #server_message = server_message.decode('utf-8')
            #so selecionar a parte da mensaagem e nao o nome do utilizador

            print(server_message)
            if ":" in server_message:
                name = server_message.split(":")[0]
                encrypted_message_hex = server_message.split(":")[1]
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                print(encrypted_message)
                decrypt_message = self.aes.decrypt_AES(encrypted_message)
            else:
                decrypt_message=""

            if not server_message.strip():
                os._exit(0)
            print("\033[1;31;40m" + name+":"+decrypt_message + "\033[0m")


if __name__ == "__main__":
    Client('localhost', 12345)