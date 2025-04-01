""" 
RSA Cipher Implementation
Current Features:
- Basic RSA encryption/decryption
- 2048-bit key generation by default
- Miller-Rabin primality test

"""
# ? this part will allow me to import from the parent directory
import sys
import os

# Gets the full path to THIS file (rsa_cipher.py)
current = os.path.dirname(os.path.realpath(__file__))

# Gets the parent directory (goes up one level from rsa/ to crpyto/)
parent = os.path.dirname(current)

# Adds that parent directory to Python's search path
sys.path.append(parent)
# ? =================================================

# Import base crypto class 
from base import AsymetricCrypto

# Standard library imports
import random
import math
from typing import Tuple

class RSA_Cipher(AsymetricCrypto):
    def __init__(
            self,
            private_key=None, 
            public_key=None, 
            key_size=2048
    ):
        self.key_size = key_size
        super().__init__(None, None)
        if not self.public_key:
            self.generate_key()

    def generate_key(self) -> Tuple[str, str]:
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        n = p * q
        # Euler's Totient Function φ(n) = (p-1) * (q-1)
        phi_n = (p - 1) * (q - 1)
        e = 65537 # commonly used public exponent
        d = pow(e, -1, phi_n) # private exponent d = e^(-1) mod φ(n)
        
        public_key = f"{n},{e}"
        private_key = f"{n},{d}"

        return public_key, private_key

    def encrypt(
            self, 
            plaintext: str) -> str:
        n, e = map(int, self.public_key.split(","))
        plaintext_int = int.from_bytes(plaintext.encode('utf-8'), 'big')
        if plaintext_int >= n:
           raise ValueError("message too long for key size")
        # c = m^e mod n
        ciphertext_int = pow(plaintext_int, e, n)  
        ciphertext = str(ciphertext_int) 

        return ciphertext
    
    def decrypt(
            self, 
            ciphertext: str) -> str:
        n, d = map(int, self.private_key.split(","))
        ciphertext_int = int(ciphertext)
         # m = c^d mod n
        plaintext_int = pow(ciphertext_int, d, n)
        plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode('utf-8') 

        return plaintext

    # Helper methods
    def _generate_prime(self, bits: int) -> int:
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        while True:
            number = random.getrandbits(bits) | (1 << bits - 1) | 1
            for p in small_primes:
                if number % p == 0 and number != p:
                   break
            else:
            # Miller-Rabin test
                if self._is_prime(number):
                   return number

    
    def _is_prime(self, n: int, k: int = 5) -> bool: 
        # small numbers logic
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False
        # writing n as d*2^s + 1
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1 
        # repeat test k times
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n) # a^d mod n
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n) # square x
                if x == n - 1:
                    break
            else:
                return False # composite
        return True # prime

if __name__ == "__main__":
    rsa = RSA_Cipher(key_size=2048) 
    public_key, private_key = rsa.generate_key()

    # print("public key:", public_key)
    # print("private key:", private_key)

    message = "test"
    encrypted = rsa.encrypt(message)
    print("encrypted:", encrypted)

    decrypted = rsa.decrypt(encrypted)
    print("decrypted:", decrypted)