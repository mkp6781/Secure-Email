import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class UserInterface:
    def __init__(self):
        pass

    def load_keys(self, sender: str, reciever: str, keysize: str):
        # Loading private and public key of reciever and sender.
        with open(f"{sender}_priv_{keysize}.txt", "rb") as key_file:
            sender_private_key = serialization.load_pem_private_key(key_file.read(), password=b'password',)
        sender_public_key = sender_private_key.public_key()

        with open(f"{reciever}_priv_{keysize}.txt", "rb") as key_file:
            reciever_private_key = serialization.load_pem_private_key(key_file.read(), password=b'password',)
        reciever_public_key = reciever_private_key.public_key()
        return sender_private_key, sender_public_key, reciever_private_key, reciever_public_key

    def ReadMail(self, pgp_type: str, sender: str, reciever: str, secure_in: str, plaintext_out: str, hash_alg: str, enc_alg: str, keysize: str):
        # Loading private and public key of sender and reciever.
        sender_private_key, sender_public_key, reciever_private_key, reciever_public_key = self.load_keys(sender, reciever, keysize)

        # Reading the secure message and key or digest from input file.
        with open(secure_in, "rb") as secure_input:
            # The last character is a newline character. Hence it is excluded.
            encrypted_digest_or_key_b64 = secure_input.readline()[:-1]
            plain_or_encrypted_message = secure_input.read()

        if enc_alg == "des-ede3-cbc":
            block_size_in_bytes = 8
            symmetric_cipher = algorithms.TripleDES
        elif enc_alg == "aes-256-cbc":
            block_size_in_bytes = 16
            symmetric_cipher = algorithms.AES

        # Assigning hashing function.
        if hash_alg == "sha3-512":
            hashing_func = hashes.SHA3_512
        elif hash_alg == "sha512":
            hashing_func = hashes.SHA512

        if pgp_type == "CONF":
            encrypted_secret_key = base64.b64decode(encrypted_digest_or_key_b64)
            encrypted_data = base64.b64decode(plain_or_encrypted_message)

            # Decrypt encrypted_secret_key using reciever's private key
            secret_key_and_iv = reciever_private_key.decrypt(
                encrypted_secret_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Separating the initialisation vector from the key. In RSA, size of iv is the data block size.
            iv = secret_key_and_iv[-1*block_size_in_bytes:]
            secret_key = secret_key_and_iv[:-1*block_size_in_bytes]
            cipher = Cipher(symmetric_cipher(secret_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_original_message_bytes = decryptor.update(encrypted_data)
            unpadder = pad.PKCS7(128).unpadder()
            original_message_bytes = unpadder.update(padded_original_message_bytes)
            original_message_bytes+=unpadder.finalize()
            original_message = original_message_bytes.decode('utf-8')

        elif pgp_type == "AUIN":
            plaintext_message = plain_or_encrypted_message
            encrypted_hash_digest = base64.b64decode(encrypted_digest_or_key_b64)
            # Calculating hash of plain message for comparing with decrypted hash digest.
            # If calculated hash and decrypted value match Authentication and Integrity is achieved. 
            sender_public_key.verify(
                encrypted_hash_digest,
                plaintext_message,
                padding.PSS(
                    mgf=padding.MGF1(hashing_func()),
                    salt_length=padding.PSS.MAX_LENGTH
                ), hashing_func()
            )
            print("Hashes match. Data integrity and authentication achieved.")
            original_message = plaintext_message.decode('utf-8')

        elif pgp_type == "COAI":
            encrypted_secret_key = base64.b64decode(encrypted_digest_or_key_b64)
            encrypted_data = base64.b64decode(plain_or_encrypted_message)

            # Decrypt encrypted_secret_key using reciever's private key.
            secret_key_and_iv = reciever_private_key.decrypt(
                encrypted_secret_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Separating the initialisation vector from the key.
            iv = secret_key_and_iv[-1*block_size_in_bytes:]
            secret_key = secret_key_and_iv[:-1*block_size_in_bytes]
            cipher = Cipher(symmetric_cipher(secret_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_original_message_bytes = decryptor.update(encrypted_data)
            unpadder = pad.PKCS7(128).unpadder()
            original_message_bytes = unpadder.update(padded_original_message_bytes)
            original_message_bytes+=unpadder.finalize()

            if int(keysize) == 1024:
                hash_digest_end_index = 128
            elif int(keysize) == 2048:
                hash_digest_end_index = 256

            encrypted_hash_bytes = original_message_bytes[:hash_digest_end_index]
            original_message = original_message_bytes[hash_digest_end_index:]
            original_message = original_message.decode('utf-8')
            
        with open(plaintext_out, "w") as output:
            output.write(original_message)


    def CreateMail(self, pgp_type: str, sender: str, reciever: str, mail_in: str, mail_out: str, hash_alg: str, enc_alg: str, keysize: str):
        sender_private_key, sender_public_key, reciever_private_key, reciever_public_key = self.load_keys(sender, reciever, keysize)

        # Obtaining message to be send in bytes.
        with open(mail_in, "rb") as mail_input:
            message = mail_input.read()

        # Encryption using AES or Triple DES symmetric block cipher algorithm.
        if enc_alg == "des-ede3-cbc":
            secret_key_size_in_bytes = 24
            block_size_in_bytes = 8
            symmetric_cipher = algorithms.TripleDES
        elif enc_alg == "aes-256-cbc":
            secret_key_size_in_bytes = 32
            block_size_in_bytes = 16
            symmetric_cipher = algorithms.AES

        # For secret key size of fixed byte size.
        secret_key = os.urandom(secret_key_size_in_bytes)
        iv = os.urandom(block_size_in_bytes)
        cipher = Cipher(symmetric_cipher(secret_key), modes.CBC(iv))

        # Encrypted hash digest from message.
        if hash_alg == "sha3-512":
            hashing_func = hashes.SHA3_512 
        elif hash_alg == "sha512":
            hashing_func = hashes.SHA512 

        encrypted_hash = sender_private_key.sign(
                                        message,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashing_func()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ), hashing_func())

        # Choosing email encryption based on security type.
        if pgp_type == "CONF":
            encryptor = cipher.encryptor()
            padder = pad.PKCS7(128).padder()
            padded_data = padder.update(message)
            padded_data+=padder.finalize()
            cipher_text = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_secret_key = reciever_public_key.encrypt(
                                            (secret_key+iv),
                                            padding.OAEP(
                                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label=None
                                            )
                                        )
            line1_bytes = base64.b64encode(encrypted_secret_key)
            line2_bytes = base64.b64encode(cipher_text)

        elif pgp_type == "AUIN":
            line1_bytes = base64.b64encode(encrypted_hash)
            line2_bytes = message

        elif pgp_type == "COAI":
            message_with_hash = encrypted_hash + message
            encryptor = cipher.encryptor()
            padder = pad.PKCS7(128).padder()
            padded_data = padder.update(message_with_hash)
            padded_data+=padder.finalize()
            cipher_text = encryptor.update(padded_data) + encryptor.finalize()
            # encrypting secret key with reciever's public key.
            encrypted_secret_key = reciever_public_key.encrypt(
                                                (secret_key+iv),
                                                padding.OAEP(
                                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(),
                                                    label=None
                                                )
                                            )
            line1_bytes = base64.b64encode(encrypted_secret_key)
            line2_bytes = base64.b64encode(cipher_text)

        with open(mail_out, "wb") as mail_output:
            mail_output.write(line1_bytes)
            mail_output.write(b"\n")
            mail_output.write(line2_bytes)

    def CreateKeys(self, filename: str, keysize: str):
        # Generate key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=int(keysize), backend=None)
        # Write key to disk for safe keeping
        with open(filename, "r") as f:
            while True:
                username = f.readline()
                username = username.rstrip("\n")
                if not username:
                    break
                with open(f"{username}_priv_{keysize}.txt", "wb") as pr:
                    pr.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
                    ))
                public_key = private_key.public_key()
                with open(f"{username}_pub_{keysize}.txt", "wb") as pu:
                    pu.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ))