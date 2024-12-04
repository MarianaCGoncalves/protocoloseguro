import socket
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend 
from threading import Thread

class Server:
    Clients = []

    def __init__(self, HOST, PORT):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((HOST, PORT))
        self.socket.listen(10)
        print("Server listening on port {} and waiting for connections...".format(PORT))

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            print("Connection from: " + str(client_address))

            client_name = client_socket.recv(1024).decode()
            client = {'client_name': client_name, 'client_socket': client_socket}

            with open ('keys/'+client_name+'_privkey.pem', "r") as f:
                client_key = f.read()
                
            user_cert = self.generate_user_certificate(client_name, client_key)
            #client_socket.send(user_cert.public_bytes(serialization.Encoding.PEM))

            self.broadcast_message(client_name, client_name + " has joined.")
            Server.Clients.append(client)
            Thread(target = self.handle_new_client, args = (client,)).start()


    def handle_new_client(self, client):
        client_name = client['client_name']
        client_socket = client['client_socket']

        while True:
            client_message = client_socket.recv(1024).decode()

            if client_message.strip() == client_name + ": bye" or not client_message.strip():
                self.broadcast_message(client_name, client_name + " has left.")
                Server.Clients.remove(client)
                client_socket.close()
                break
            else:
                self.broadcast_message(client_name, client_message)

    def broadcast_message(self, sender_name, message):
        for client in Server.Clients:
            client_socket = client['client_socket']
            client_name = client['client_name']
            if client_name != sender_name:
                client_socket.send(message.encode())

    def generate_user_certificate(self, user_name, user_key):
            
            user_key = user_key.encode('utf-8')
            user_key = serialization.load_pem_private_key(user_key, password= b"passphrase", backend=default_backend())
            # Create a CSR for the user
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, user_name),
            ])).sign(user_key, hashes.SHA256())

            # Sign the CSR with the CA's private key to create the user's certificate

            #ca_key = rsa.generate_private_key(
                #public_exponent=65537,
                #key_size=4096
            #)

            with open ("keys/gateway_key.pem", "rb") as gateway_key:
                ca_key = serialization.load_pem_private_key(
                    gateway_key.read(),
                    password=b"passphrase",
                    backend=default_backend()
                )

            ca_cert = x509.CertificateBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Lisboa"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Iscte-Sintra"),
                    x509.NameAttribute(NameOID.COMMON_NAME, user_name)
                ])
            ).issuer_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Lisboa"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Iscte-Sintra"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "ISCTE CA")
                ])
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(ca_key, hashes.SHA256())

            user_cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(ca_key, hashes.SHA256())

            with open("certs/"+user_name+"_cert.pem","wb") as file: 
                file.write(user_cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    server = Server("localhost", 12345)
    server.listen()