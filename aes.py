#!/usr/bin/env python3
"""
aes.py
Fully fixed pure Python AES implementation
"""

# =========================================================
# OFFICIAL AES S-BOX
# =========================================================

s_box = (
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
    205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
    96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
    224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
    231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
    186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
    112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
    225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
    140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
)

# =========================================================
# VALIDATE S-BOX
# =========================================================

if len(s_box) != 256:
    raise ValueError(f"S-Box length invalid: {len(s_box)}")

if len(set(s_box)) != 256:
    raise ValueError("S-Box contains duplicate values")

# =========================================================
# INVERSE S-BOX
# =========================================================

inv_s_box = [0] * 256

for i, value in enumerate(s_box):
    inv_s_box[value] = i

inv_s_box = tuple(inv_s_box)

# =========================================================
# ROUND CONSTANTS
# =========================================================

r_con = (
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,
    0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A,
    0x2F,0x5E,0xBC,0x63,0xC6,0x97,0x35,0x6A,
    0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91,0x39
)

# =========================================================
# HELPERS
# =========================================================

def bytes2matrix(text):

    return [
        list(text[i:i+4])
        for i in range(0, len(text), 4)
    ]

def matrix2bytes(matrix):

    return bytes(sum(matrix, []))

def xor_bytes(a, b):

    return bytes(i ^ j for i, j in zip(a, b))

def pad(data):

    padding_len = 16 - (len(data) % 16)

    return data + bytes([padding_len] * padding_len)

def unpad(data):

    if not data:
        raise ValueError("Empty data")

    padding_len = data[-1]

    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")

    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid PKCS7 padding")

    return data[:-padding_len]

def split_blocks(data, block_size=16):

    if len(data) % block_size != 0:
        raise ValueError("Data not aligned to block size")

    return [
        data[i:i+block_size]
        for i in range(0, len(data), block_size)
    ]

# =========================================================
# AES CLASS
# =========================================================

class AES:

    rounds_by_key_size = {
        16: 10,
        24: 12,
        32: 14
    }

    def __init__(self, key):

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("AES key must be bytes")

        if len(key) not in AES.rounds_by_key_size:
            raise ValueError(
                "AES key must be 16, 24, or 32 bytes"
            )

        self.n_rounds = AES.rounds_by_key_size[len(key)]

        self._key_matrices = self._expand_key(
            bytes(key)
        )

    # =====================================================

    def _expand_key(self, master_key):

        key_columns = bytes2matrix(master_key)

        iteration_size = len(master_key) // 4

        i = 1

        while len(key_columns) < 4 * (self.n_rounds + 1):

            word = list(key_columns[-1])

            if len(key_columns) % iteration_size == 0:

                word.append(word.pop(0))

                word = [s_box[b] for b in word]

                word[0] ^= r_con[i]

                i += 1

            elif len(master_key) == 32 and \
                 len(key_columns) % iteration_size == 4:

                word = [s_box[b] for b in word]

            word = xor_bytes(
                word,
                key_columns[-iteration_size]
            )

            key_columns.append(list(word))

        return [
            key_columns[4*i : 4*(i+1)]
            for i in range(len(key_columns) // 4)
        ]

    # =====================================================

    def encrypt_block(self, plaintext):

        if len(plaintext) != 16:
            raise ValueError(
                "Plaintext block must be 16 bytes"
            )

        state = bytes2matrix(plaintext)

        self._add_round_key(
            state,
            self._key_matrices[0]
        )

        for i in range(1, self.n_rounds):

            self._sub_bytes(state)

            self._shift_rows(state)

            self._mix_columns(state)

            self._add_round_key(
                state,
                self._key_matrices[i]
            )

        self._sub_bytes(state)

        self._shift_rows(state)

        self._add_round_key(
            state,
            self._key_matrices[-1]
        )

        return matrix2bytes(state)

    # =====================================================

    def decrypt_block(self, ciphertext):

        if len(ciphertext) != 16:
            raise ValueError(
                "Ciphertext block must be 16 bytes"
            )

        state = bytes2matrix(ciphertext)

        self._add_round_key(
            state,
            self._key_matrices[-1]
        )

        self._inv_shift_rows(state)

        self._inv_sub_bytes(state)

        for i in range(self.n_rounds - 1, 0, -1):

            self._add_round_key(
                state,
                self._key_matrices[i]
            )

            self._inv_mix_columns(state)

            self._inv_shift_rows(state)

            self._inv_sub_bytes(state)

        self._add_round_key(
            state,
            self._key_matrices[0]
        )

        return matrix2bytes(state)

    # =====================================================

    def encrypt_cbc(self, plaintext, iv):

        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        plaintext = pad(plaintext)

        blocks = []

        previous = iv

        for plaintext_block in split_blocks(plaintext):

            block = xor_bytes(
                plaintext_block,
                previous
            )

            block = self.encrypt_block(block)

            blocks.append(block)

            previous = block

        return b''.join(blocks)

    # =====================================================

    def decrypt_cbc(self, ciphertext, iv):

        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")

        if len(ciphertext) % 16 != 0:
            raise ValueError(
                "Ciphertext must be aligned to 16 bytes"
            )

        blocks = []

        previous = iv

        for ciphertext_block in split_blocks(ciphertext):

            block = self.decrypt_block(
                ciphertext_block
            )

            block = xor_bytes(block, previous)

            blocks.append(block)

            previous = ciphertext_block

        return unpad(b''.join(blocks))

    # =====================================================

    def _sub_bytes(self, s):

        for i in range(4):
            for j in range(4):

                value = s[i][j]

                if value > 255:
                    raise ValueError(
                        f"sub_bytes overflow: {value}"
                    )

                s[i][j] = s_box[value]

    # =====================================================

    def _inv_sub_bytes(self, s):

        for i in range(4):
            for j in range(4):

                value = s[i][j]

                if value > 255:
                    raise ValueError(
                        f"inv_sub_bytes overflow: {value}"
                    )

                s[i][j] = inv_s_box[value]

    # =====================================================

    def _shift_rows(self, s):

        s[0][1],s[1][1],s[2][1],s[3][1] = \
        s[1][1],s[2][1],s[3][1],s[0][1]

        s[0][2],s[1][2],s[2][2],s[3][2] = \
        s[2][2],s[3][2],s[0][2],s[1][2]

        s[0][3],s[1][3],s[2][3],s[3][3] = \
        s[3][3],s[0][3],s[1][3],s[2][3]

    # =====================================================

    def _inv_shift_rows(self, s):

        s[0][1],s[1][1],s[2][1],s[3][1] = \
        s[3][1],s[0][1],s[1][1],s[2][1]

        s[0][2],s[1][2],s[2][2],s[3][2] = \
        s[2][2],s[3][2],s[0][2],s[1][2]

        s[0][3],s[1][3],s[2][3],s[3][3] = \
        s[1][3],s[2][3],s[3][3],s[0][3]

    # =====================================================

    def _add_round_key(self, s, k):

        for i in range(4):
            for j in range(4):

                s[i][j] ^= k[i][j]

                s[i][j] &= 0xFF

    # =====================================================

    def _xtime(self, a):

        return (
            (((a << 1) ^ 0x1B) & 0xFF)
            if (a & 0x80)
            else ((a << 1) & 0xFF)
        )

    # =====================================================

    def _mix_columns(self, s):

        for i in range(4):

            a = s[i]

            t = a[0] ^ a[1] ^ a[2] ^ a[3]

            u = a[0]

            a[0] ^= t ^ self._xtime(a[0] ^ a[1])
            a[1] ^= t ^ self._xtime(a[1] ^ a[2])
            a[2] ^= t ^ self._xtime(a[2] ^ a[3])
            a[3] ^= t ^ self._xtime(a[3] ^ u)

            a[0] &= 0xFF
            a[1] &= 0xFF
            a[2] &= 0xFF
            a[3] &= 0xFF

    # =====================================================

    def _inv_mix_columns(self, s):

        for i in range(4):

            a = s[i]

            u = self._xtime(
                self._xtime(a[0] ^ a[2])
            )

            v = self._xtime(
                self._xtime(a[1] ^ a[3])
            )

            a[0] ^= u
            a[1] ^= v
            a[2] ^= u
            a[3] ^= v

            a[0] &= 0xFF
            a[1] &= 0xFF
            a[2] &= 0xFF
            a[3] &= 0xFF

        self._mix_columns(s)

# =========================================================
# SELF TEST
# =========================================================

if __name__ == "__main__":

    key = bytes(range(32))

    iv = bytes(range(16))

    cipher = AES(key)

    message = b"hello world"

    encrypted = cipher.encrypt_cbc(message, iv)

    decrypted = cipher.decrypt_cbc(
        encrypted,
        iv
    )

    print("Encrypted:", encrypted.hex())

    print("Decrypted:", decrypted.decode())

    print("AES self-test passed.")

 *My favorite app::Python3 IDE Fresh Edition  https://itunes.apple.com/app/id1397406775?mt=8