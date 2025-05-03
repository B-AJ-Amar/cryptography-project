import pytest
from .crpyto.rsa.rsa_cipher import RSA_Cipher
from .steganography.image import SteganographyLSBImage

from .crpyto.playfair.playfair_chipher import (
    DefaultPlayfairConfig,
    UseNullPlayfairConfig,
    NoNullPlayfairConfig,
    PlayfairCipher
)
from .crpyto.polybius_square.polybius_square_chipher import (
    DefaultPolybiusSquareConfig,
    UseNullPolybiusSquareConfig,
    NoNullPolybiusSquareConfig,
    PolybiusSquareCipher
)


@pytest.mark.parametrize("key, config, plaintext, expected", [
    ("KEY", DefaultPlayfairConfig(), "HELLO", "DBNVTB"),
    ("KEY", UseNullPlayfairConfig(), "HELLO", ";'N°`-"),
    ("KEY", NoNullPlayfairConfig(), "HELLO", "C!U¨L'"),
])
def test_playfair_encrypt(key, config, plaintext, expected):
    cipher = PlayfairCipher(key, config)
    assert cipher.encrypt(plaintext) == expected


@pytest.mark.parametrize("key, config, ciphertext, expected", [
    ("KEY", DefaultPlayfairConfig(), "DBNVTB", "HELLOZ"),
    ("KEY", UseNullPlayfairConfig(), ";'N°`-", "HELLO\x00"),
    ("KEY", NoNullPlayfairConfig(), "C!U¨L'", "HELLO$"),
])
def test_playfair_decrypt(key, config, ciphertext, expected):
    cipher = PlayfairCipher(key, config)
    assert cipher.decrypt(ciphertext) == expected


@pytest.mark.parametrize("key, config, plaintext, expected", [
    ("KEY", DefaultPolybiusSquareConfig(), "HELLO", "4 1 1 0 1 2 1 2 4 2 "),
    ("KEY", UseNullPolybiusSquareConfig(), "HELLO", "13 2 1 0 0 3 0 3 3 3 "),
    ("KEY", NoNullPolybiusSquareConfig(), "HELLO", "5 2 1 0 8 2 8 2 11 2 "),
])
def test_polybius_encrypt(key, config, plaintext, expected):
    cipher = PolybiusSquareCipher(key, config)
    assert cipher.encrypt(plaintext) == expected


@pytest.mark.parametrize("key, config, ciphertext, expected", [
    ("KEY", DefaultPolybiusSquareConfig(), "4 1 1 0 1 2 1 2 4 2 ", "HELLO"),
    ("KEY", UseNullPolybiusSquareConfig(), "13 2 1 0 0 3 0 3 3 3 ", "HELLO"),
    ("KEY", NoNullPolybiusSquareConfig(), "5 2 1 0 8 2 8 2 11 2 ", "HELLO"),
])
def test_polybius_decrypt(key, config, ciphertext, expected):
    cipher = PolybiusSquareCipher(key, config)
    assert cipher.decrypt(ciphertext) == expected


def test_rsa_encrypt_decrypt():
    rsa = RSA_Cipher(key_size=512)
    plaintext = "HELLO RSA"
    ciphertext = rsa.encrypt(plaintext)
    decrypted_text = rsa.decrypt(ciphertext)
    assert decrypted_text == plaintext


def test_steganography_encode_decode(tmp_path):
    steganography = SteganographyLSBImage()
    input_image = "./test_image.png"  # Replace with a valid test image path
    output_image = tmp_path / "output_image.png"
    data = "Hidden Message"

    # Encode
    steganography.encode(data, input_image, str(output_image))

    # Decode
    decoded_data = steganography.decode(str(output_image))
    assert decoded_data == data+"\x01"