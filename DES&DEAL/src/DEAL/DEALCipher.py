from src.FeistelNetwork import FeistelNetwork
from src.interfaces import ISymmetricCipher, IDESAdapter
from src.DES.DESCipher import DESCipher
from src.DES.DESKeyExpansion import DESKeyExpansion
from src.DEAL.DEALKeyExpansion import DEALKeyExpansion
from src.DEAL.DEALEncryptor import DEALEncryptor
import asyncio


class DESAdapter(IDESAdapter):
    def __init__(self, key: bytes):
        self.des = DESCipher()
        key_expansion = DESKeyExpansion()
        round_keys = key_expansion.generate_round_keys(key)
        self.des.set_round_keys(round_keys)

    @property
    def block_size(self) -> int:
        return 8

    def encrypt_block(self, block: bytes) -> bytes:
        return self.des.encrypt_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self.des.decrypt_block(block)

    async def encrypt_block_async(self, block: bytes) -> bytes:
        return await self.des.encrypt_block_async(block)

    async def decrypt_block_async(self, block: bytes) -> bytes:
        return await self.des.decrypt_block_async(block)


class DEALCipher(FeistelNetwork, ISymmetricCipher):
    def __init__(self, key: bytes):
        key_size = len(key)
        
        if key_size not in (16, 24, 32):
            raise ValueError('Ключ для DEAL должен быть 16 (DEAL-128), 24 (DEAL-192), or 32 (DEAL-256) bytes')

        key_expansion = DEALKeyExpansion()
        des_adapter = DESAdapter(key[:8])
        encryptor = DEALEncryptor(des_adapter)
        
        block_size = 16
        rounds = 6 if key_size == 16 else 8

        super().__init__(
            key_expansion=key_expansion,
            encryptor=encryptor,
            master_key=key,
            block_size=block_size,
            rounds=rounds
        )
        
        self.key_size = key_size

    @property
    def key_size_info(self) -> str:
        return f'DEAL-{self.key_size * 8}'

    async def encrypt_block_async(self, block: bytes) -> bytes:
        return await asyncio.to_thread(self.encrypt_block, block)

    async def decrypt_block_async(self, block: bytes) -> bytes:
        return await asyncio.to_thread(self.decrypt_block, block)