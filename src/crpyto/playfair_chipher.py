"""
this function is an inhanced version of the playfair cipher
there are some problems in the original playfair cipher like :
    - if the text contain the letter "j" it will be replaced with "i"
    - does not support numbers and special characters and Upper case letters
    - there is a confusion between "i" and "j"

this version will solve these problems and add some features like :
    - support numbers and special characters and Upper case letters
    - support any key


my base table is like:
['\x00','\t', '\n',' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
'2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D',
'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}',
'~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯', '°', '±',
'²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á', 'Â', 'Ã',
'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ',
'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç',
'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù',
'ú', 'û', 'ü', 'ý', 'þ', 'ÿ']

- if the text is impair i will put '$\x00' at the end

TODO : add unicode support

"""

from base import SymetricCrypto
from constants import (
    PLAYFAIR_USE_NULL,
    PLAYFAIR_NO_NULL,
    PLAYFAIR_DUP_CHARS,
    PLAYFAIR_USE_NULL_WIDTH,
    PLAYFAIR_USE_NULL_HEIGHT,
    PLAYFAIR_NO_NULL_WIDTH,
    PLAYFAIR_NO_NULL_HEIGHT,
)


class PlayfairCipher(SymetricCrypto):
    def __init__(
        self, key: str, use_null: bool = True, duplicated_char: str = PLAYFAIR_DUP_CHARS
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
        self.use_null = use_null
        self.duplicated_char = duplicated_char
        if use_null:
            self.table = PLAYFAIR_USE_NULL
            self.max_width = PLAYFAIR_USE_NULL_WIDTH
            self.max_height = PLAYFAIR_USE_NULL_HEIGHT
        else:
            self.table = PLAYFAIR_NO_NULL
            self.max_width = PLAYFAIR_NO_NULL_WIDTH
            self.max_height = PLAYFAIR_NO_NULL_HEIGHT
        self.table_len = self.max_height * self.max_width
        self.make_table(key)

    def transform(
        self,
        data: str,
        shift: int = 1,
        original_state: bool = True,
        output_file: str = None,
    ) -> str:
        data, len_data = self.refactor_data(data)
        encrypted_data = ""
        for i in range(0, len_data, 2):
            if data[i] == data[i + 1]:
                data[i + 1] = self.duplicated_char

            pos1 = self.get_position(data[i])
            pos2 = self.get_position(data[i + 1])

            if pos1[0] == pos2[0]:
                new_pos1 = self.v_shift(pos1, shift=shift)
                new_pos2 = self.v_shift(pos2, shift=shift)
                encrypted_data += self.table[new_pos1[2]]
                encrypted_data += self.table[new_pos2[2]]

            elif pos1[1] == pos2[1]:
                new_pos1 = self.h_shift(pos1, shift=shift)
                new_pos2 = self.h_shift(pos2, shift=shift)
                encrypted_data += self.table[new_pos1[2]]
                encrypted_data += self.table[new_pos2[2]]

            else:
                encrypted_data += self.table[pos1[1] * self.max_width + pos2[0]]
                encrypted_data += self.table[pos2[1] * self.max_width + pos1[0]]

        if shift == -1 and original_state:
            encrypted_data = list(encrypted_data)
            # find self.duplicated_char and replace them by thair previous char
            for i in range(1, len(encrypted_data)):
                if encrypted_data[i] == self.duplicated_char:
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
        position = self.table.index(char)

        return (position % self.max_width, position // self.max_width, position)

    def v_shift(self, position: tuple, shift: int = 1) -> tuple:
        """
        this function will shift the position down/up by shift
        """
        x, y, abs_pos = position
        y += shift
        y = self.max_height + y if y < 0 else y % self.max_height
        abs_pos = y * self.max_width + x
        return (x, y, abs_pos)

    def h_shift(self, position: tuple, shift: int = 1) -> tuple:
        """
        this function will shift the position right/left by shift
        """
        x, y, abs_pos = position
        x += shift
        x = self.max_width + x if x < 0 else x % self.max_width
        abs_pos = y * self.max_width + x
        return (x, y, abs_pos)

    def make_table(self, key: str) -> str:
        key, _ = self.refactor_key(key)

        for x in key:
            self.table.remove(x)

        self.table = key + self.table

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
            data += "\x00" if self.use_null else "\n"
            len_data += 1

        return list(data), len_data


# ? some tests
if __name__ == "__main__":
    playfair = PlayfairCipher("myKey")
    print(playfair.decrypt(playfair.encrypt("hello world")))
    print(playfair.decrypt(playfair.encrypt("A")))
    print(playfair.decrypt(playfair.encrypt("this is A t3xt f@& T£s¶ 123\n")))