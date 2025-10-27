from typing import List
from src.interfaces import IKeyExpansion
from src.utils.constants import DESConstants, BitOrder
from src.utils.bit_utils import permutation, rotate_left, bits_to_bytes, bytes_to_bits


class DESKeyExpansion(IKeyExpansion):
    def generate_round_keys(self, key: bytes) -> List[bytes]:
        if len(key) != 8:
            raise ValueError("Некорректный размер исходного ключа. Ожидается, что он равен 8 байтам")

        permuted = permutation(key, DESConstants.PC1, start_at_zero=False)
        permuted_bits = bytes_to_bits(permuted, BitOrder.MSB)

        c = permuted_bits[:28]
        d = permuted_bits[28:56]

        round_keys = []
        for i in range(16):
            c = rotate_left(c, DESConstants.SHIFTS[i])
            d = rotate_left(d, DESConstants.SHIFTS[i])

            cd_bits = c + d
            cd_bytes = bits_to_bytes(cd_bits, BitOrder.MSB)  

            round_key = permutation(cd_bytes, DESConstants.PC2, start_at_zero=False)
            round_keys.append(round_key)

        return round_keys