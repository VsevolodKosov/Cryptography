import asyncio
from src.interfaces import IEncryptor
from src.utils.constants import DESConstants, BitOrder
from src.utils.bit_utils import permutation, bytes_to_bits, bits_to_bytes, xor_bytes

class DESEncryptor(IEncryptor):
    def Feistel_function(self, input_block: bytes, round_key: bytes) -> bytes:
        if len(input_block) != 4:
            raise ValueError('Некорректный размер входного блока данных. Ожидается, что размер равен 4 байтам')
        if len(round_key) != 6:
            raise ValueError('Некорректный размер раундового ключа. Ожидается, что размер равен 6 байтам')

        expanded = permutation(input_block, DESConstants.E, start_at_zero=False)
        mixed = xor_bytes(expanded, round_key)

        mixed_bits = bytes_to_bits(mixed, BitOrder.MSB)

        s_output = []
        for s_index in range(8):
            chunk = mixed_bits[s_index * 6 : s_index * 6 + 6] # Срезы по шесть бит с шагом в шесть бит

            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]

            four_bit_value = DESConstants.S[s_index][row][col]

            s_output.append((four_bit_value>> 3) & 1)
            s_output.append((four_bit_value >> 2) & 1)
            s_output.append((four_bit_value >> 1) & 1)
            s_output.append(four_bit_value & 1)

        s_output_bytes = bits_to_bytes(s_output, BitOrder.MSB)
        return permutation(s_output_bytes, DESConstants.P, start_at_zero=False)

    async def Feistel_function_async(self, input_block, round_key):
        return await asyncio.to_thread(self.Feistel_function, input_block, round_key)