import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from utils.utility import Utility

class Analyzer:
    def __init__(self, data_service, visualize=False):
        self.visualize = visualize
        self.data_service = data_service

    def test_key(self, iv, counter, key, plaintext, expected):
        try:
            current_key = (
                iv
                + counter.to_bytes(length=self.data_service.COUNTER_SIZE, byteorder="little", signed=False)
                + key
            )

            cipher = Cipher(
                algorithm=algorithms.ARC4(current_key), mode=None, backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext)

            return ciphertext == expected

        except Exception as e:
            return False

    def attack(self):
        test_plaintext = self.data_service.random_bytes(self.data_service.PLAINTEXT_SIZE)
        test_iv = self.data_service.random_bytes(self.data_service.IV_SIZE)
        test_counter = random.randint(0, 1000)
        test_ciphertext = bytes.fromhex(
            self.data_service.encrypt(test_iv.hex(), test_counter, test_plaintext.hex())
        )

        key = b""
        
        while not self.test_key(test_iv, test_counter, key, test_plaintext, test_ciphertext):
            possible_bytes = []

            for counter, keystream in self.data_service.ciphers:
                known_bytes = self.data_service.iv + counter + key
                num_known_bytes = len(known_bytes)

                S = [i for i in range(256)]

                j = 0
                for i in range(num_known_bytes):
                    j = (j + S[i] + known_bytes[i]) % 256
                    S[i], S[j] = S[j], S[i]

                output_byte = keystream[num_known_bytes - 1]
                next_S_i = (num_known_bytes - output_byte) % 256

                for x in range(256):
                    if S[x] == next_S_i:
                        pre_i = x
                        break

                key_byte = (pre_i - j - S[num_known_bytes]) % 256

                possible_bytes.append(key_byte)

            if self.visualize:
                Utility.plot_frequencies(possible_bytes, f'charts/{i}.png')

            guessed_byte = Utility.most_common_element(possible_bytes)
            key += bytes([guessed_byte])


            print(f'Byte #{len(key)} of main_key: ', guessed_byte)

        return key