"""
this function is an inhanced version of the playfair cipher
there are some problems in the original playfair cipher like :
    - if the text contain the letter "j" it will be replaced with "i"
    - does not support numbers and special characters and Upper case letters
    - there is a confusion between "i" and "j"

this version will solve these problems and add some features like :
    - support numbers and special characters and Upper case letters
    - support any key

- if the text is impair i will put '$\x00' at the end

Note : there are 3 kind of playfair configuration in my implementation :
    - DefaultPlayfairConfig : this configuration will use only uppercase letters and will replace "j" with "i"
    - UseNullPlayfairConfig : this configuration will use all the ascii table and use null char '\x00' to complete the impair text
    - NoNullPlayfairConfig :  like the previous one but not use null char '\x00' and `\t`

TODO : add unicode support

"""
"""
we should use these classes to organize our code, e.g RSA should inherit from AsymetricCrypto
"""
# !!! I GOT A PROBLEM WITH THE IMPORTS SO I HARD CODED EVERY THING
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


# ? this part will allow me to import from the parent directory
from abc import ABC

class PlayfairConfig(ABC):
    def __init__(self, table:list, width:int, height:int, duplicated_char:int, impair_char:int):
        self.table = table
        self.max_width = width
        self.max_height = height
        self.duplicated_char = duplicated_char
        self.impair = impair_char
        
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
    
    def refactor_data(self, data: str) -> str:
        len_data = len(data)
        if len_data % 2 != 0:
            data += self.impair
            len_data += 1

        return list(data), len_data
    
    def make_table(self, key: str) -> str:
        key, _ = self.refactor_key(key)
        for x in key:
            self.table.remove(x)

        self.table = key + self.table
    

class DefaultPlayfairConfig(PlayfairConfig):
    '''this class is the default configuration for the playfair cipher using only uppercase'''
    def __init__(self, duplicated_char: str='X', impair_char: str='Z'):
          self.table = [
                'A', 'B', 'C', 'D', 'E', 
                'F', 'G', 'H', 'I', 'K', 
                'L', 'M', 'N', 'O', 'P', 
                'Q', 'R', 'S', 'T', 'U', 
                'V', 'W', 'X', 'Y', 'Z'
          ]
          self.max_width = 5
          self.max_height = 5
          self.impair = impair_char
          self.duplicated_char = duplicated_char
    
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
    
    def refactor_data(self, data: str) -> str:
        data = data.upper().replace("J", "I")
        data = ''.join([i for i in data if i.isalpha()])
        len_data = len(data)
        if len_data % 2 != 0:
            data += self.impair
            len_data += 1

        return list(data), len_data
          
class UseNullPlayfairConfig(PlayfairConfig):
    def __init__(self, duplicated_char: str='²', impair_char: str='\x00'):
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
        self.impair = impair_char
        self.duplicated_char = duplicated_char
            
            
class NoNullPlayfairConfig(PlayfairConfig):
    def __init__(self, duplicated_char: str='²', impair_char: str='$\n'):
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
        self.impair = impair_char
        self.duplicated_char = duplicated_char


# ? =================================================


class PlayfairCipher(SymetricCrypto):
    def __init__(
        self,
        key: str,
        config: PlayfairConfig = UseNullPlayfairConfig(),
    ):
        """
        key : str : the key to use in the cipher
        duplicated_char : str : the char that we should replace with in case of duplicated chars example : 'aa' => 'a{duplicated_char}'
        use_null : bool : if True will use '\x00' in the table and to complete the text if it is impair

        - if use_null is True will use '\x00 :
                so the table wil contains 192 elements (16*12)

            - if use_null is False will use we will remove `\t` and `\x00` and space
                (because if we remove only null char we will have 191 elements its prime number so we can't make a table with it)
                so the table wil contains 190 elements (19*10)

        """
        super().__init__(key)
        self.config = config
        self.key = self.config.refactor_key(key)
        self.config.make_table(key)

    def transform(
        self,
        data: str,
        shift: int = 1,
        original_state: bool = True,
        output_file: str = None,
    ) -> str:
        data, len_data = self.config.refactor_data(data)
        encrypted_data = ""
        for i in range(0, len_data, 2):
            if data[i] == data[i + 1]:
                data[i + 1] = self.config.duplicated_char

            pos1 = self.get_position(data[i])
            pos2 = self.get_position(data[i + 1])

            if pos1[0] == pos2[0]:
                new_pos1 = self.v_shift(pos1, shift=shift)
                new_pos2 = self.v_shift(pos2, shift=shift)
                encrypted_data += self.config.table[new_pos1[2]]
                encrypted_data += self.config.table[new_pos2[2]]

            elif pos1[1] == pos2[1]:
                new_pos1 = self.h_shift(pos1, shift=shift)
                new_pos2 = self.h_shift(pos2, shift=shift)
                encrypted_data += self.config.table[new_pos1[2]]
                encrypted_data += self.config.table[new_pos2[2]]

            else:
                encrypted_data += self.config.table[
                    pos1[1] * self.config.max_width + pos2[0]
                ]
                encrypted_data += self.config.table[
                    pos2[1] * self.config.max_width + pos1[0]
                ]

        if shift == -1 and original_state:
            encrypted_data = list(encrypted_data)
            # find self.config.duplicated_char and replace them by thair previous char
            for i in range(1, len(encrypted_data)):
                if encrypted_data[i] == self.config.duplicated_char:
                    encrypted_data[i] = encrypted_data[i - 1]

            encrypted_data = "".join(encrypted_data)
        if output_file:
            with open(output_file, "w") as f:
                f.write(encrypted_data)

        return encrypted_data

    def encrypt(self, data: str, output_file: str = None) -> str:
        return self.transform(data=data, shift=1, output_file=output_file)

    def decrypt(self, data: str, output_file: str = None) -> str:
        return self.transform(data=data, shift=-1, output_file=output_file)

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

    def v_shift(self, position: tuple, shift: int = 1) -> tuple:
        """
        this function will shift the position down/up by shift
        """
        x, y, abs_pos = position
        y += shift
        y = self.config.max_height + y if y < 0 else y % self.config.max_height
        abs_pos = y * self.config.max_width + x
        return (x, y, abs_pos)

    def h_shift(self, position: tuple, shift: int = 1) -> tuple:
        """
        this function will shift the position right/left by shift
        """
        x, y, abs_pos = position
        x += shift
        x = self.config.max_width + x if x < 0 else x % self.config.max_width
        abs_pos = y * self.config.max_width + x
        return (x, y, abs_pos)


# ? some tests
if __name__ == "__main__":
    playfair = PlayfairCipher("myKey")
    print(playfair.decrypt(playfair.encrypt("hello world")))
    print(playfair.decrypt(playfair.encrypt("A")))
    print(playfair.decrypt(playfair.encrypt("this is A t3xt f@& T£s¶ 123\n")))
