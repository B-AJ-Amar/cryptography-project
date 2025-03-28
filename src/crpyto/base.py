"""
we should use these classes to organize our code, e.g RSA should inherit from AsymetricCrypto
"""

from abc import ABC
from typing import Tuple


class Crypro(ABC):
    def encrypt(self, data: str) -> str:
        pass

    def decrypt(self, data: str) -> str:
        pass


class SymetricCrypto(Crypro):
    def __init__(self, key):
        self.key = key

    def generate_key(self) -> str:
        pass

    def get_key(self) -> str:
        return self.key

    def set_key(self, key: str):
        self.key = key


class AsymetricCrypto(Crypro):
    def __init__(self, private_key: str = None, public_key: str = None):
        if private_key is None and public_key is None:
            public_key, private_key = self.generate_key()
        self.private_key = private_key
        self.public_key = public_key

    def generate_key(self) -> Tuple[str, str]:
        pass

    def get_public_key(self) -> str:
        return self.public_key

    def get_private_key(self) -> str:
        return self.private_key

    def set_key(self, private_key: str, public_key: str):
        self.private_key = private_key
        self.public_key = public_key
