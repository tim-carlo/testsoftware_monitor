#This code is needed to compute CRC32 checksums in Python, matching the C implementation.

class CRC32:
    WIDTH = 32
    POLYNOMIAL = 0x04C11DB7  # Standard CRC32 polynomial (IEEE 802.3)
    INITIAL_REMAINDER = 0xFFFFFFFF
    FINAL_XOR_VALUE = 0xFFFFFFFF
    TOPBIT = 1 << (WIDTH - 1)

    def __init__(self):
        self.table = self.generate_crc_table()

    @staticmethod
    def reflect(data: int, nBits: int) -> int:
        reflection = 0
        for bit in range(nBits):
            if data & 0x01:
                reflection |= (1 << ((nBits - 1) - bit))
            data >>= 1
        return reflection

    @classmethod
    def generate_crc_table(cls):
        table = []
        for dividend in range(256):
            curr = cls.reflect(dividend, 8) << (cls.WIDTH - 8)
            for _ in range(8):
                if curr & cls.TOPBIT:
                    curr = (curr << 1) ^ cls.POLYNOMIAL
                else:
                    curr <<= 1
            table.append(cls.reflect(curr, cls.WIDTH) & 0xFFFFFFFF)
        return table

    def crcFast(self, message: bytes) -> int:
        remainder = self.INITIAL_REMAINDER
        for byte in message:
            data = self.reflect(byte, 8) ^ (remainder >> (self.WIDTH - 8))
            remainder = self.table[data] ^ ((remainder << 8) & 0xFFFFFFFF)
        return (self.reflect(remainder, self.WIDTH) ^ self.FINAL_XOR_VALUE) & 0xFFFFFFFF