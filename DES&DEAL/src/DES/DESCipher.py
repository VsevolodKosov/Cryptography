from src.FeistelNetwork import FeistelNetwork
from src.DES.DESKeyExpansion import DESKeyExpansion
from src.DES.DESEncryptor import DESEncryptor
from src.interfaces import ISymmetricCipher
from src.utils.bit_utils import permutation
from src.utils.constants import DESConstants, BitOrder
import asyncio


class DESCipher(FeistelNetwork, ISymmetricCipher):
    def __init__(self, master_key: bytes = None):
        key_expansion = DESKeyExpansion()
        encryptor = DESEncryptor()
        super().__init__(
            key_expansion=key_expansion,
            encryptor=encryptor,
            master_key=master_key,
            block_size=8,
            rounds=16
        )

    def encrypt_block(self, block: bytes) -> bytes:
        block = permutation(block, DESConstants.IP, start_at_zero=False, bit_order=BitOrder.MSB)
        result = super().encrypt_block(block)
        return permutation(result, DESConstants.IP_INV, start_at_zero=False, bit_order=BitOrder.MSB)

    def decrypt_block(self, block: bytes) -> bytes:
        block = permutation(block, DESConstants.IP, start_at_zero=False, bit_order=BitOrder.MSB)
        result = super().decrypt_block(block)
        return permutation(result, DESConstants.IP_INV, start_at_zero=False, bit_order=BitOrder.MSB)

    async def encrypt_block_async(self, block: bytes) -> bytes:
        return await asyncio.to_thread(self.encrypt_block, block)

    async def decrypt_block_async(self, block: bytes) -> bytes:
        return await asyncio.to_thread(self.decrypt_block, block)