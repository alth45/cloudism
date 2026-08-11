"""
AES-256 implementasi manual (educational purpose only).
Mode operasi: CTR (Counter mode).
"""

import os
from cloudsim.crypto.utils import xor_bytes

# S-Box (standar AES)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [0]*256
for i in range(256):
    INV_SBOX[SBOX[i]] = i

# Rcon untuk ekspansi kunci
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def sub_bytes(state):
    return [SBOX[b] for b in state]

def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def shift_rows(state):
    # state: 16-byte list, urutan kolom-mayor (column-major)
    # baris ke-1 geser 0, ke-2 geser 1, ke-3 geser 2, ke-4 geser 3
    s = list(state)
    # Indeks: 0 4 8  12
    #         1 5 9  13
    #         2 6 10 14
    #         3 7 11 15
    # setelah geser:
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s

def inv_shift_rows(state):
    s = list(state)
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    return s

def xtime(a):
    """Multiply by 2 in GF(2^8)"""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def mix_single_column(col):
    # col adalah list 4 byte [c0,c1,c2,c3]
    c0, c1, c2, c3 = col
    d0 = xtime(c0) ^ xtime(c1) ^ c1 ^ c2 ^ c3
    d1 = xtime(c1) ^ xtime(c2) ^ c0 ^ c2 ^ c3
    d2 = xtime(c2) ^ xtime(c3) ^ c0 ^ c1 ^ c3
    d3 = xtime(c3) ^ xtime(c0) ^ c0 ^ c1 ^ c2
    return [d0 & 0xff, d1 & 0xff, d2 & 0xff, d3 & 0xff]

def mix_columns(state):
    # state 16 bytes column-major: kolom 0: indeks 0,1,2,3; kolom 1: 4,5,6,7 dst.
    new = []
    for i in range(4):
        col = state[i*4 : i*4+4]
        new.extend(mix_single_column(col))
    return new

def inv_mix_single_column(col):
    c0, c1, c2, c3 = col
    # multiply by 14,11,13,9
    d0 = mult(0x0e, c0) ^ mult(0x0b, c1) ^ mult(0x0d, c2) ^ mult(0x09, c3)
    d1 = mult(0x09, c0) ^ mult(0x0e, c1) ^ mult(0x0b, c2) ^ mult(0x0d, c3)
    d2 = mult(0x0d, c0) ^ mult(0x09, c1) ^ mult(0x0e, c2) ^ mult(0x0b, c3)
    d3 = mult(0x0b, c0) ^ mult(0x0d, c1) ^ mult(0x09, c2) ^ mult(0x0e, c3)
    return [d0 & 0xff, d1 & 0xff, d2 & 0xff, d3 & 0xff]

def mult(a, b):
    """Multiply in GF(2^8)"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        b >>= 1
        a = xtime(a)
    return p & 0xff

def inv_mix_columns(state):
    new = []
    for i in range(4):
        col = state[i*4 : i*4+4]
        new.extend(inv_mix_single_column(col))
    return new

def add_round_key(state, round_key):
    return xor_bytes(state, round_key)

# Ekspansi kunci AES-256
def key_expansion_256(key):
    """
    key: 32 bytes (256-bit)
    Menghasilkan 60 word (240 byte) untuk 14 round + 1 add_round_key awal.
    """
    Nk = 8  # 256-bit: 8 word
    Nr = 14
    Nb = 4
    # Konversi ke list word 32-bit sebagai integer
    w = []
    for i in range(Nk):
        w.append(int.from_bytes(key[4*i:4*i+4], 'big'))
    for i in range(Nk, Nb*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            # RotWord
            temp = ((temp << 8) & 0xffffffff) | (temp >> 24)
            # SubWord
            b0 = SBOX[(temp >> 24) & 0xff]
            b1 = SBOX[(temp >> 16) & 0xff]
            b2 = SBOX[(temp >> 8) & 0xff]
            b3 = SBOX[temp & 0xff]
            temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
            # XOR Rcon
            temp ^= (RCON[i//Nk - 1] << 24)
        elif Nk > 6 and i % Nk == 4:
            # SubWord for 256-bit
            b0 = SBOX[(temp >> 24) & 0xff]
            b1 = SBOX[(temp >> 16) & 0xff]
            b2 = SBOX[(temp >> 8) & 0xff]
            b3 = SBOX[temp & 0xff]
            temp = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        w.append(w[i-Nk] ^ temp)
    # Kembalikan sebagai list 16-byte round keys
    round_keys = []
    for i in range(0, len(w), 4):
        rk = b""
        for j in range(4):
            rk += w[i+j].to_bytes(4, 'big')
        round_keys.append(rk)
    return round_keys

def aes_encrypt_block(block, key):
    """
    block: 16 bytes
    key: 32 bytes (AES-256)
    """
    state = list(block)
    round_keys = key_expansion_256(key)
    # Add round key awal
    state = add_round_key(state, list(round_keys[0]))
    # Round 1..13
    for r in range(1, 14):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, list(round_keys[r]))
    # Round terakhir (14) tanpa MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, list(round_keys[14]))
    return bytes(state)

def aes_decrypt_block(block, key):
    state = list(block)
    round_keys = key_expansion_256(key)
    # Add round key terakhir
    state = add_round_key(state, list(round_keys[14]))
    # Inverse round 13..1
    for r in range(13, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, list(round_keys[r]))
        state = inv_mix_columns(state)
    # Final round (ke-0) tanpa InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, list(round_keys[0]))
    return bytes(state)

# Mode CTR
class AES256CTR:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Kunci harus 32 bytes (256-bit)")
        self.key = key

    def encrypt(self, plaintext: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
        """
        Enkripsi dalam mode CTR.
        nonce: 8 bytes (opsional, auto-generate jika tidak ada)
        Return: (ciphertext, nonce)
        """
        if nonce is None:
            nonce = os.urandom(8)
        # counter: 8 byte nonce + 8 byte counter (big-endian integer)
        counter = 0
        ciphertext = bytearray()
        blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
        for block in blocks:
            # Buat counter block
            ctr_block = nonce + counter.to_bytes(8, 'big')
            keystream = aes_encrypt_block(ctr_block, self.key)
            ct = xor_bytes(block, keystream[:len(block)])
            ciphertext.extend(ct)
            counter += 1
        return bytes(ciphertext), nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Dekripsi sama persis dengan enkripsi CTR."""
        # Karena symmetric
        plaintext, _ = self.encrypt(ciphertext, nonce)
        return plaintext