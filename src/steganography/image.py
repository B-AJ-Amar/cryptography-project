from PIL import Image
from abc import ABC, abstractmethod


class Steganography(ABC):
    @abstractmethod
    def encode(self, data: str, file_path: str, output_path: str) -> None:
        pass

    @abstractmethod
    def decode(self, file_path: str) -> str:
        pass

    @abstractmethod
    def open_file(self, file_path: str):
        pass


class SteganographyLSBImage(Steganography):
    def __init__(self):
        super().__init__()
        self.END = "1" + "0" * 16
        # self.LSB_COUNT = 1 # in this test we will use only 1 bit

    def encode(
        self,
        data: str,
        file_path: str = "image/3840x2160.png",
        output_path: str = "out.png",
    ) -> None:
        image, pixels = self.open_file(file_path)

        data_bin = [format(ord(i), "08b") for i in data]
        data_bin.append(self.END)
        data_bin = "".join(data_bin)
        len_bin = len(data_bin)
        bit_ptr, x, y = 0, 0, 0
        for y in range(image.height):
            for x in range(image.width):
                if len_bin == bit_ptr:
                    break
                px = list(pixels[x, y])  # rgb(a) in case of transparancy suport

                for i in range(3):
                    if len_bin == bit_ptr:
                        break

                    """
                    explanation:
                    px[i] & ~1: clear the least significant bit of the pixel
                        ~1: 11111110  (in binary)
                        px[i] & ~1: clear the least significant bit of the pixel
                    int(data_bin[bit_ptr]): get the bit to be inserted
                    """
                    px[i] = (px[i] & ~1) | int(data_bin[bit_ptr])
                    bit_ptr += 1

                pixels[x, y] = tuple(px)
            if len_bin == 0:
                break
        image.save(output_path)

    def decode(self, file_path: str = "out.png", output_path: str = "out.txt") -> str:
        image, pixels = self.open_file(file_path)
        data_bin = ""
        bit_ptr = 0
        end = False
        for y in range(image.height):
            for x in range(image.width):
                px = list(pixels[x, y])
                for i in range(3):
                    data_bin += str(px[i] % 2)
                    bit_ptr += 1
                if bit_ptr > 17 and self.END in data_bin[-20:]:
                    end = True
                    break
            if end:
                break

        data_bin = data_bin[:-16]
        data = [data_bin[i : i + 8] for i in range(0, len(data_bin), 8)]

        data = "".join([chr(int(i, 2)) for i in data])

        with open(output_path, "w") as f:
            f.write(data)

        return data

    def open_file(self, file_path: str):
        image = Image.open(file_path)
        pixels = image.load()  # does it suports transparancy

        return image, pixels


if __name__ == "__main__":
    Steganography = SteganographyLSBImage()
    Steganography.encode("Wello world1NFAKJB398=-sn", "image/3840x2160.png", "out.png")
    print(Steganography.decode("out.png","out.txt"))
