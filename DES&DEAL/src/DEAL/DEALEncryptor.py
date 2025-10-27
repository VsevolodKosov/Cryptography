from src.interfaces import IEncryptor, IDESAdapter
from src.utils.bit_utils import xor_bytes


class DEALEncryptor(IEncryptor):
    def __init__(self, des_adapter: IDESAdapter):
        self.des_adapter = des_adapter

    def Feistel_function(self, input_block: bytes, round_key: bytes) -> bytes:
        xored = xor_bytes(input_block, round_key)
        return self.des_adapter.encrypt_block(xored)

    async def Feistel_function_async(self, input_block: bytes, round_key: bytes) -> bytes:
        xored = xor_bytes(input_block, round_key)
        
        if hasattr(self.des_adapter, 'encrypt_block_async'):
            return await self.des_adapter.encrypt_block_async(xored)
        else:
            return self.des_adapter.encrypt_block(xored)