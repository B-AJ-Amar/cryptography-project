""" 
RSA Cipher Implementation

Features:
- RSA encryption and decryption
- Automatic key generation 
- Supports variable key sizes (default: 2048 bits)
- Handles large messages by splitting into chunks
- UTF-8 encoding for plaintext

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
from typing import Tuple, List

class RSA_Cipher(AsymetricCrypto):
    def __init__(
            self,
            private_key="", 
            public_key="", 
            key_size=2048
    ):
        self.key_size = key_size
        super().__init__(private_key, public_key)
        if not self.public_key and not self.private_key:
            self.generate_key()

    def can_encrypt(self):
        return bool(self.public_key)
    
    def can_decrypt(self):
        return bool(self.private_key)
    
    def generate_key(self) -> Tuple[str, str]:
        p = self._generate_prime(self.key_size // 2)
        q = self._generate_prime(self.key_size // 2)
        n = p * q
        # Euler's Totient Function φ(n) = (p-1) * (q-1)
        phi_n = (p - 1) * (q - 1)
        e = 65537 # commonly used public exponent
        d = pow(e, -1, phi_n) # private exponent d = e^(-1) mod φ(n)
        
        self.public_key = f"{n},{e}"
        self.private_key = f"{n},{d}"

        return self.public_key, self.private_key

    def encrypt(
            self, 
            plaintext: str) -> str:
        if not plaintext:
            raise ValueError("plaintext can't be empty")
        if not self.can_encrypt():
            raise ValueError("no public key available for encryption")
        
        n, e = self._parse_key(self.public_key)
        max_chunk_size = self._calculate_max_chunk_size(n)
        plaintext_bytes = plaintext.encode('utf-8')
        chunks = self._split_into_chunks(plaintext_bytes, max_chunk_size)
        encrypted_chunks = [] 
        for chunk in chunks:
            plaintext_int = int.from_bytes(chunk, 'big')
            if plaintext_int >= n:
                raise ValueError("message too long for key size")
            # c = m^e mod n
            ciphertext_int = pow(plaintext_int, e, n)  
            encrypted_chunks.append(str(ciphertext_int))

        cyphertexet = "|".join(encrypted_chunks)
        return  cyphertexet
    
    def decrypt(
            self, 
            ciphertext: str) -> str:
        if not ciphertext:
            raise ValueError("ciphertext can't be empty")
        if not self.can_decrypt():
            raise ValueError("No private key available for decryption")
        if not all(chunk.isdigit() for chunk in ciphertext.split("|")):
            raise ValueError("invalid format")
        
        n, d = self._parse_key(self.private_key)
        encrypted_chunks = ciphertext.split("|")
        decrypted_chunks = []
        for chunk in encrypted_chunks:
            ciphertext_int = int(chunk)
            # m = c^d mod n
            plaintext_int = pow(ciphertext_int, d, n)
            chunk_bytes = plaintext_int.to_bytes(
                max(1, (plaintext_int.bit_length() + 7) // 8),'big')
            decrypted_chunks.append(chunk_bytes)
        
        plaintext = b''.join(decrypted_chunks).decode('utf-8')
        return plaintext

    # helper methods
    def _parse_key(self, 
                   key_str: str) -> Tuple[int, int]:
        try:
            return tuple(map(int, key_str.split(',')))
        except:
            raise ValueError("invalid format")

    def _calculate_max_chunk_size(self,
                                   n: int) -> int:
        return (n.bit_length() - 1) // 8  

    def _split_into_chunks(self,
                            data: bytes,
                              chunk_size: int) -> List[bytes]:
        return [data[i:i + chunk_size] 
                for i in range(0, len(data), chunk_size)]
    
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

  print("public key:", rsa.public_key)
  print("private key:", rsa.private_key)

  message = "test"
  encrypted = rsa.encrypt(message)
  print("encrypted:", encrypted)

  decrypted = rsa.decrypt(encrypted)
  print("decrypted:", decrypted)
