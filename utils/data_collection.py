import os
import csv
import random

from random import choice
from string import ascii_uppercase

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from operator import xor



class DataService:
    IV_SIZE = int(os.getenv("IV_SIZE")) if os.getenv("IV_SIZE") else 16
    COUNTER_SIZE =  int(os.getenv("COUNTER_SIZE")) if os.getenv("COUNTER_SIZE") else 3
    KEY_SIZE = int(os.getenv("KEY_SIZE")) if os.getenv("KEY_SIZE") else 13
    PLAINTEXT_SIZE = int(os.getenv("PLAINTEXT_SIZE")) if os.getenv("PLAINTEXT_SIZE") else 48

    def __init__(self, key=None, filename=None, ):
        if not key:
            self.key = self.generate_key()
        else: 
            self.key = key
        
        if filename: 
            self.save_file = filename
            self.load_ciphers()
        else:
            self._iv = None
            self._ciphers = []

    def encrypt(self, iv, counter, data):
        try:
            iv = bytes.fromhex(iv)
            if (len(iv) != self.IV_SIZE): raise Exception("Iv size does not match")

            if counter < 0: raise Exception("Counter must be positive")
            counter = counter.to_bytes(length=self.COUNTER_SIZE, byteorder="little", signed=False)
            
            data = bytes.fromhex(data)
            if (len(data) != self.PLAINTEXT_SIZE): raise Exception("Plaintext size does not match")

        except Exception as e:
            print(e)
            return False

        key = iv + counter + self.key

        cipher = Cipher(
            algorithm=algorithms.ARC4(key), mode=None, backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext_bytes = encryptor.update(data)

        return ciphertext_bytes.hex()
    
    def random_bytes(self, length):
        return bytes(random.sample(range(256), length))

    def generate_ciphers(self, num_samples): 
        if self.ciphers == []:
            self._iv = self.random_bytes(self.IV_SIZE)
            for counter in range(num_samples):
                plaintext = self.random_bytes(self.PLAINTEXT_SIZE)

                encrypted = self.encrypt(self.iv.hex(), counter, plaintext.hex())
                if encrypted:
                    ciphertext = bytes.fromhex(
                       encrypted
                    )

                    keystream = bytes([xor(pt, ct) for pt, ct in zip(plaintext, ciphertext)])

                    counter = counter.to_bytes(
                        length=self.COUNTER_SIZE, byteorder="little", signed=False
                    )
                    self.ciphers.append((counter, keystream))
        if self.save_file:
            self.save_ciphers()

    def generate_key(self):
        key = ''.join(choice(ascii_uppercase) for _ in range(self.KEY_SIZE)) 
        return bytes(key, "utf-8")

    @property
    def ciphers(self):
        return self._ciphers

    @property
    def iv(self):
        return self._iv

    def save_ciphers(self): 
        try:
            with open(self.save_file, "w", newline="") as cache_file:
                writer = csv.writer(cache_file)
                for counter, keystream in self.ciphers:
                    writer.writerow([self.iv.hex(), counter.hex(), keystream.hex()])

        except Exception as e:
            print(e)

    def load_ciphers(self):
        try:
            ciphers = []
            iv = None

            with open(self.save_file, "r", newline="") as ciphers_file:
                reader = csv.reader(ciphers_file)
                for row in reader:
                    iv = bytes.fromhex(row[0])
                    ciphers.append((bytes.fromhex(row[1]), bytes.fromhex(row[2])))

        except Exception as e:
            print(e)

        self._iv = iv
        self._ciphers = ciphers

