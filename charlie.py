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

    def send_message(self):
        while True:
            client_input = input("")
            client_message = self.name + ": " + client_input
            self.socket.send(client_message.encode())

    def receive_message(self):
        while True:
            server_message = self.socket.recv(1024).decode()
            if not server_message.strip():
                os._exit(0)
            print("\033[1;31;40m" + server_message + "\033[0m")


if __name__ == "__main__":
    Client('localhost', 12345)