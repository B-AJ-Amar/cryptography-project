"""
basicly i used the same idea i used in the playfair
TODO : add unicode support

"""

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




class PolybiusSquareConfig(ABC):
    def __init__(self, table:list, width:int, height:int):
        self.table = table
        self.max_width = width
        self.max_height = height

        
    def refactor_key(self, key: str) -> list: 
        """
        this function will refactor the key to remove duplicates
        """
        new = []
        len_key = len(key)
        for i in range(len_key):
            if key[i] not in new:
                new.append(key[i])
        return new, len_key
    
    def refactor_data(self, data: str) -> list:
        return list(data)
    
    def make_table(self, key: str) -> str:
        key, _ = self.refactor_key(key)
        for x in key:
            self.table.remove(x)

        self.table = key + self.table
    

class DefaultPolybiusSquareConfig(PolybiusSquareConfig):
    '''this class is the default configuration for the PolybiusSquare cipher using only uppercase'''
    def __init__(self):
          self.table = [
                'A', 'B', 'C', 'D', 'E', 
                'F', 'G', 'H', 'I', 'K', 
                'L', 'M', 'N', 'O', 'P', 
                'Q', 'R', 'S', 'T', 'U', 
                'V', 'W', 'X', 'Y', 'Z'
          ]
          self.max_width = 5
          self.max_height = 5
          
    
    def refactor_key(self, key: str) -> list: 
        """
        this function will refactor the key to remove duplicates
        """
        key = key.upper().replace("J", "I")
        new = []
        len_key = len(key)
        for i in range(len_key):
            if key[i] not in new: new.append(key[i])
        
        return new, len_key
    
    def refactor_data(self, data: str) -> list:
        data = data.upper().replace("J", "I")
        data = ''.join([i for i in data if i.isalpha()])

        return list(data)
          
class UseNullPolybiusSquareConfig(PolybiusSquareConfig):
    def __init__(self):
        self.table = [
            '\x00', '\t', '\n', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',',
            '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<',
            '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
            'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',
            ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|',
            '}', '~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯',
            '°', '±', '²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿',
            'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï',
            'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß',
            'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï',
            'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ'
        ]
        self.max_width = 16
        self.max_height = 12

            
            
class NoNullPolybiusSquareConfig(PolybiusSquareConfig):
    def __init__(self):
        self.table = [
            '\n', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
            '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
            'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}',
            '~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯', '°', '±', '²', '³',
            '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ',
            'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', '×', 'Ø', 'Ù',
            'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì',
            'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ',
        ]
        self.max_width = 19
        self.max_height = 10

# ? =================================================




class PolybiusSquareCipher(SymetricCrypto):
    def __init__(
        self,
        key: str = "",
        config: PolybiusSquareConfig = UseNullPolybiusSquareConfig(),
    ):
        super().__init__(key)
        self.config = config
        self.key = self.config.refactor_key(key)
        self.config.make_table(key)

    def encrypt(
        self,
        data: str,
        output_file: str = None,
    ) -> str:
        data = self.config.refactor_data(data)
        encrypted_data = ""
        for x in data:
            position = self.get_position(x)
            # if position[2] == -1:
            #     continue

            encrypted_data += f"{str(position[0])} {str(position[1])} "

        if output_file:
            with open(output_file, "w") as f:
                f.write(encrypted_data)

        return encrypted_data

    def decrypt(self, data: str, output_file: str = None) -> str:
        decrypted_data = ""
        data = data.split(" ")
        for x in range(0, len(data) - 1, 2):
            position = int(data[x]), int(data[x + 1])
            decrypted_data += self.get_char(position[0], position[1])

        return decrypted_data

    def get_position(self, char: str) -> tuple:
        """
        this function will return the position of the char in the table (x,y, absolute position)
        """
        position = self.config.table.index(char)

        return (
            position % self.config.max_width,
            position // self.config.max_width,
            position,
        )

    def get_char(self, x: int, y: int) -> str:
        """
        this function will return the char in the table at position x,y
        """
        return self.config.table[y * self.config.max_width + x]


# ? some tests
if __name__ == "__main__":
    PolybiusSquare = PolybiusSquareCipher()
    print(PolybiusSquare.encrypt("hello world1@"))
    print(PolybiusSquare.decrypt(PolybiusSquare.encrypt("hello world")))
    print(PolybiusSquare.decrypt(PolybiusSquare.encrypt("A")))
    print(
        PolybiusSquare.decrypt(PolybiusSquare.encrypt("this is A t3xt f@& T£s¶ 123\n"))
    )
