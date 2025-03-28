"""
basicly i used the same idea i used in the playfair
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

from polybius_square_conf import PolybiusSquareConfig, UseNullPolybiusSquareConfig


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
