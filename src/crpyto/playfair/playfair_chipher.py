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

# ? this part will allow me to import from the parent directory
import sys
import os

# getting the name of the directory
# where the this file is present.
current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to
# the sys.path.
sys.path.append(parent)
# ? =================================================

from base import SymetricCrypto

from playfair_conf import PlayfairConfig, UseNullPlayfairConfig


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
