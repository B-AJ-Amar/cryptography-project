s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# Round constants
r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def sub_bytes(s):
    """Apply SubBytes transformation using the S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def inv_sub_bytes(s):
    """Apply inverse SubBytes transformation using the inverse S-box."""
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]

def shift_rows(s):
    """Apply ShiftRows transformation (left shifts)."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    """Apply inverse ShiftRows transformation (right shifts)."""
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    """Add round key to the state matrix."""
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    """Mix a single column in MixColumns."""
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    """Apply MixColumns transformation."""
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    """Apply inverse MixColumns transformation."""
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)

def bytes2matrix(text):
    return [list(text[i::4]) for i in range(4)]

def matrix2bytes(matrix):
    return bytes(sum(zip(*matrix), ()))

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

SHA256_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def sha256(message: bytes) -> bytes:
    """Pure Python SHA-256 implementation."""
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    length = len(message) * 8  
    message += b'\x80'
    while (len(message) + 8) % 64 != 0:
        message += b'\x00'
    message += length.to_bytes(8, 'big')

    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        w = [0] * 64

        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], 'big')

        for j in range(16, 64):
            s0 = (right_rotate(w[j-15], 7) ^ right_rotate(w[j-15], 18) ^ (w[j-15] >> 3))
            s1 = (right_rotate(w[j-2], 17) ^ right_rotate(w[j-2], 19) ^ (w[j-2] >> 10))
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for j in range(64):
            S1 = (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25))
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + SHA256_CONSTANTS[j] + w[j]) & 0xFFFFFFFF
            S0 = (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return b''.join(x.to_bytes(4, 'big') for x in [h0, h1, h2, h3, h4, h5, h6, h7])

def right_rotate(n, b):
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

class AES:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        if len(master_key) not in self.rounds_by_key_size:
            raise ValueError("Key must be 16, 24, or 32 bytes.")
        self.n_rounds = self.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)


    def encrypt_cbc(self, plaintext, iv):
        """Encrypts multi-block data using CBC mode."""
        plaintext = pad(plaintext)
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = b''
        prev = iv
        for block in blocks:
            block = xor_bytes(block, prev)
            encrypted = self.encrypt_block(block)
            ciphertext += encrypted
            prev = encrypted
        return ciphertext

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypts multi-block CBC data."""
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = b''
        prev = iv
        for block in blocks:
            decrypted = self.decrypt_block(block)
            plaintext += xor_bytes(decrypted, prev)
            prev = block
        return unpad(plaintext)

    @staticmethod
    def hmac_sha256(key, message):
        """HMAC-SHA256 implementation."""
        if len(key) > 64:
            key = sha256(key)
        if len(key) < 64:
            key += b'\x00' * (64 - len(key))
        
        o_key_pad = xor_bytes(key, b'\x5c' * 64)
        i_key_pad = xor_bytes(key, b'\x36' * 64)
        
        return sha256(o_key_pad + sha256(i_key_pad + message))

def generate_iv():
    """Generate a random initialization vector."""
    import os
    return os.urandom(16)

b64_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def custom_b64encode(data):
    """Correct Base64 encoding implementation without external libraries."""
    result = []
    padding_len = (3 - len(data) % 3) % 3
    data = data + b'\x00' * padding_len  
    
    for i in range(0, len(data), 3):
        chunk = data[i:i+3]
        bits = (chunk[0] << 16) | (chunk[1] << 8) | chunk[2]
        
        result.append(b64_alphabet[(bits >> 18) & 0x3F])
        result.append(b64_alphabet[(bits >> 12) & 0x3F])
        result.append(b64_alphabet[(bits >> 6) & 0x3F])
        result.append(b64_alphabet[bits & 0x3F])
    
    if padding_len > 0:
        result[-padding_len:] = ['='] * padding_len
    
    return ''.join(result)

def custom_b64decode(s):
    """Base64 Decoding without external libraries."""
    s = s.rstrip('=')
    result = bytearray()
    bits = 0
    bit_count = 0

    for char in s:
        if char not in b64_alphabet:
            continue  
        idx = b64_alphabet.index(char)
        bits = (bits << 6) | idx
        bit_count += 6

        if bit_count >= 8:
            bit_count -= 8
            result.append((bits >> bit_count) & 0xFF)
            bits &= (1 << bit_count) - 1

    return bytes(result)

def pad(data):
    """PKCS#7 Padding."""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    """Remove PKCS#7 Padding."""
    padding_len = data[-1]
    if not 1 <= padding_len <= 16:
        raise ValueError("Invalid padding length.")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding.")
    return data[:-padding_len]


class AES:
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        if len(master_key) not in self.rounds_by_key_size:
            raise ValueError("Key must be 16, 24, or 32 bytes.")
        self.n_rounds = self.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        i = 1

        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0)) 
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1

            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            key_columns.append([key_columns[-iteration_size][j] ^ word[j] for j in range(4)])

        return [key_columns[i:i + 4] for i in range(0, len(key_columns), 4)]

    def encrypt_block(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes.")
        state = bytes2matrix(plaintext)
        add_round_key(state, self._key_matrices[0])
        for i in range(1, self.n_rounds):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self._key_matrices[i])
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, self._key_matrices[-1])
        return matrix2bytes(state)

    def decrypt_block(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext must be 16 bytes.")
        state = bytes2matrix(ciphertext)
        add_round_key(state, self._key_matrices[-1])
        inv_shift_rows(state)
        inv_sub_bytes(state)
        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(state, self._key_matrices[i])
            inv_mix_columns(state)
            inv_shift_rows(state)
            inv_sub_bytes(state)
        add_round_key(state, self._key_matrices[0])
        return matrix2bytes(state)

    def encrypt_cbc(self, plaintext, iv):
        """Encrypts multi-block data using CBC mode."""
        plaintext = pad(plaintext)
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        ciphertext = b''
        prev = iv
        for block in blocks:
            block = xor_bytes(block, prev)
            encrypted = self.encrypt_block(block)
            ciphertext += encrypted
            prev = encrypted
        return ciphertext

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypts multi-block CBC data."""
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        plaintext = b''
        prev = iv
        for block in blocks:
            decrypted = self.decrypt_block(block)
            plaintext += xor_bytes(decrypted, prev)
            prev = block
        return unpad(plaintext)

    @staticmethod
    def hmac_sha256(key, message):
        """HMAC-SHA256 implementation."""
        if len(key) > 64:
            key = sha256(key)
        if len(key) < 64:
            key += b'\x00' * (64 - len(key))
        
        o_key_pad = xor_bytes(key, b'\x5c' * 64)
        i_key_pad = xor_bytes(key, b'\x36' * 64)
        
        return sha256(o_key_pad + sha256(i_key_pad + message))

def main():
    print("AES Encryption/Decryption with CBC and HMAC")
    operation = input("Enter operation (encrypt/decrypt): ").strip().lower()
    user_input = input("Enter input: ").strip()
    key = input("Enter key (16/24/32 chars): ").strip().encode('utf-8')
    
    aes = AES(key)

    if operation == "encrypt":
        iv = generate_iv()
        plaintext = user_input.encode('utf-8')
        
        ciphertext = aes.encrypt_cbc(plaintext, iv)
        
        hmac = aes.hmac_sha256(key, ciphertext)
        full_output = iv + hmac + ciphertext  
        
        print(f"Encrypted (Base64): {custom_b64encode(full_output)}")

    elif operation == "decrypt":
        full_input = custom_b64decode(user_input)
        iv = full_input[:16]
        hmac = full_input[16:48] 
        ciphertext = full_input[48:]
        
        expected_hmac = aes.hmac_sha256(key, ciphertext)
        if hmac != expected_hmac:
            print(" HMAC verification failed! Message may be corrupted.")
            return
            
        plaintext = aes.decrypt_cbc(ciphertext, iv)
        print(f"Decrypted: {plaintext.decode('utf-8')}")

if __name__ == "__main__":
    main()
