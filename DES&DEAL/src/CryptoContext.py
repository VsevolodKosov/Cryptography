import asyncio
from typing import List, Optional
from src.utils.constants import CipherMode, PaddingMode
from src.utils.bit_utils import xor_bytes
from src.utils.block_utils import padding, unpadding, split_blocks, join_blocks


class CryptoContext:
    def __init__(
        self,
        cipher,
        mode: CipherMode,
        padding_mode: PaddingMode,
        iv: Optional[bytes] = None
    ):
        self.cipher = cipher
        self.mode = mode
        self.padding = padding_mode
        self.iv = iv
        self.block_size = cipher.block_size
        self._validate_parameters()

    def _validate_parameters(self):
        if self.mode != CipherMode.ECB:
            if not self.iv:
                raise ValueError(f"IV обязателен для {self.mode}")
            if len(self.iv) != self.block_size:
                raise ValueError(f"IV должен быть {self.block_size} в байтах, но он {len(self.iv)}")

    def encrypt(self, data: bytes) -> bytes:
        padded_data = padding(data, self.block_size, self.padding)
        blocks = split_blocks(padded_data, self.block_size)
        
        encrypted_blocks = self.encrypt_blocks(blocks)
        
        return join_blocks(encrypted_blocks)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("Сообщение должно быть кратно размеру блоков")
        
        blocks = split_blocks(data, self.block_size)
        
        decrypted_blocks = self.decrypt_blocks(blocks)
        
        decrypted_data = join_blocks(decrypted_blocks)
        return unpadding(decrypted_data, self.padding)

    async def encrypt_async(self, data: bytes) -> bytes:
        padded_data = padding(data, self.block_size, self.padding)
        blocks = split_blocks(padded_data, self.block_size)
        
        encrypted_blocks = await self.encrypt_blocks_async(blocks)
        
        return join_blocks(encrypted_blocks)

    async def decrypt_async(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("Сообщение должно быть кратно размеру блоков)")
        
        blocks = split_blocks(data, self.block_size)
        
        decrypted_blocks = await self.decrypt_blocks_async(blocks)
        
        decrypted_data = join_blocks(decrypted_blocks)
        return unpadding(decrypted_data, self.padding)

    def encrypt_blocks(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return self.encrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self.encrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self.encrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self.encrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self.encrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self.encrypt_ctr(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return self.encrypt_random_delta(blocks)
        else:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")

    def decrypt_blocks(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return self.decrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self.decrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self.decrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self.decrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self.decrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self.decrypt_ctr(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return self.decrypt_random_delta(blocks)
        else:
            raise ValueError(f"Неподдерживаемый режим: {self.mode}")

    async def encrypt_blocks_async(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return await self.encrypt_ecb_async(blocks)
        elif self.mode == CipherMode.CTR:
            return await self.encrypt_ctr_async(blocks)
        elif self.mode == CipherMode.OFB:
            return await self.encrypt_ofb_async(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return await self.encrypt_random_delta_async(blocks)
        else:
            return self.encrypt_blocks(blocks)

    async def decrypt_blocks_async(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return await self.decrypt_ecb_async(blocks)
        elif self.mode == CipherMode.CTR:
            return await self.decrypt_ctr_async(blocks)
        elif self.mode == CipherMode.OFB:
            return await self.decrypt_ofb_async(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return await self.decrypt_random_delta_async(blocks)
        else:
            return self.decrypt_blocks(blocks)

    async def _process_parallel(self, blocks: List[bytes], encrypt: bool) -> List[bytes]:
        async def process_block(block, encrypt):
            sync_method = self.cipher.encrypt_block if encrypt else self.cipher.decrypt_block
            async_method_name = 'encrypt_block_async' if encrypt else 'decrypt_block_async'
            
            if hasattr(self.cipher, async_method_name):
                async_method = getattr(self.cipher, async_method_name)
                return await async_method(block)
            else:
                return sync_method(block)
        
        return await asyncio.gather(*[process_block(block, encrypt) for block in blocks])

    async def encrypt_ecb_async(self, blocks: List[bytes]) -> List[bytes]:
        return await self._process_parallel(blocks, True)

    async def decrypt_ecb_async(self, blocks: List[bytes]) -> List[bytes]:
        return await self._process_parallel(blocks, False)

    async def encrypt_ctr_async(self, blocks: List[bytes]) -> List[bytes]:
        counters = self._generate_counters(len(blocks))
        
        async def encrypt_counter(counter):
            if hasattr(self.cipher, 'encrypt_block_async'):
                return await self.cipher.encrypt_block_async(counter)
            else:
                return self.cipher.encrypt_block(counter)
        
        keystreams = await asyncio.gather(*[encrypt_counter(counter) for counter in counters])
        
        return [xor_bytes(block, keystream) for block, keystream in zip(blocks, keystreams)]

    async def decrypt_ctr_async(self, blocks: List[bytes]) -> List[bytes]:
        return await self.encrypt_ctr_async(blocks)

    async def encrypt_ofb_async(self, blocks: List[bytes]) -> List[bytes]:
        result = []
        keystream = self.iv
        
        for block in blocks:
            if hasattr(self.cipher, 'encrypt_block_async'):
                keystream = await self.cipher.encrypt_block_async(keystream)
            else:
                keystream = self.cipher.encrypt_block(keystream)
            result.append(xor_bytes(block, keystream))
        
        return result

    async def decrypt_ofb_async(self, blocks: List[bytes]) -> List[bytes]:
        return await self.encrypt_ofb_async(blocks)

    async def encrypt_random_delta_async(self, blocks: List[bytes]) -> List[bytes]:
        counters = self._generate_counters(len(blocks))
        
        async def process_block(counter, block):
            delta = self._generate_delta(counter)
            modified_counter = xor_bytes(counter, delta)
            
            if hasattr(self.cipher, 'encrypt_block_async'):
                keystream = await self.cipher.encrypt_block_async(modified_counter)
            else:
                keystream = self.cipher.encrypt_block(modified_counter)
            
            return xor_bytes(block, keystream)
        
        return await asyncio.gather(*[process_block(counter, block) for counter, block in zip(counters, blocks)])

    async def decrypt_random_delta_async(self, blocks: List[bytes]) -> List[bytes]:
        return await self.encrypt_random_delta_async(blocks)

    def _process_ecb(self, blocks: List[bytes], encrypt: bool) -> List[bytes]:
        method = self.cipher.encrypt_block if encrypt else self.cipher.decrypt_block
        return [method(block) for block in blocks]

    def _process_cbc(self, blocks: List[bytes], encrypt: bool) -> List[bytes]:
        result = []
        prev = self.iv
        
        if encrypt:
            for block in blocks:
                xored = xor_bytes(block, prev)
                encrypted = self.cipher.encrypt_block(xored)
                result.append(encrypted)
                prev = encrypted
        else:
            for block in blocks:
                decrypted = self.cipher.decrypt_block(block)
                plaintext = xor_bytes(decrypted, prev)
                result.append(plaintext)
                prev = block
        
        return result

    def _process_pcbc(self, blocks: List[bytes], encrypt: bool) -> List[bytes]:
        result = []
        feedback = self.iv
        
        if encrypt:
            for block in blocks:
                xored = xor_bytes(block, feedback)
                encrypted = self.cipher.encrypt_block(xored)
                result.append(encrypted)
                feedback = xor_bytes(block, encrypted)
        else:
            for block in blocks:
                decrypted = self.cipher.decrypt_block(block)
                plaintext = xor_bytes(decrypted, feedback)
                result.append(plaintext)
                feedback = xor_bytes(plaintext, block)
        
        return result

    def _process_cfb(self, blocks: List[bytes], encrypt: bool) -> List[bytes]:
        result = []
        shift_register = self.iv
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(shift_register)
            processed = xor_bytes(block, keystream)
            result.append(processed)
            shift_register = processed if encrypt else block
        
        return result

    def _process_ofb(self, blocks: List[bytes]) -> List[bytes]:
        result = []
        keystream = self.iv
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(keystream)
            result.append(xor_bytes(block, keystream))
        
        return result

    def _process_ctr(self, blocks: List[bytes]) -> List[bytes]:
        result = []
        counter = self.iv
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(counter)
            result.append(xor_bytes(block, keystream))
            counter = self._increment_counter(counter)
        
        return result

    def _process_random_delta(self, blocks: List[bytes]) -> List[bytes]:
        result = []
        counter = self.iv
        
        for block in blocks:
            delta = self._generate_delta(counter)
            modified_counter = xor_bytes(counter, delta)
            keystream = self.cipher.encrypt_block(modified_counter)
            result.append(xor_bytes(block, keystream))
            counter = self._increment_counter(counter)
        
        return result

    def encrypt_ecb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ecb(blocks, True)

    def decrypt_ecb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ecb(blocks, False)

    def encrypt_cbc(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_cbc(blocks, True)

    def decrypt_cbc(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_cbc(blocks, False)

    def encrypt_pcbc(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_pcbc(blocks, True)

    def decrypt_pcbc(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_pcbc(blocks, False)

    def encrypt_cfb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_cfb(blocks, True)

    def decrypt_cfb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_cfb(blocks, False)

    def encrypt_ofb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ofb(blocks)

    def decrypt_ofb(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ofb(blocks)

    def encrypt_ctr(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ctr(blocks)

    def decrypt_ctr(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_ctr(blocks)

    def encrypt_random_delta(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_random_delta(blocks)

    def decrypt_random_delta(self, blocks: List[bytes]) -> List[bytes]:
        return self._process_random_delta(blocks)

    def _generate_counters(self, count: int) -> List[bytes]:
        counters = []
        current_counter = self.iv
        
        for _ in range(count):
            counters.append(current_counter)
            current_counter = self._increment_counter(current_counter)
        
        return counters

    def _generate_delta(self, counter: bytes) -> bytes:
        delta = bytearray(len(counter))
        
        for i, c in enumerate(counter):
            delta[i] = (c * 17 + i * 13) % 256
        
        return bytes(delta)

    def _increment_counter(self, counter: bytes) -> bytes:
        arr = bytearray(counter)
        
        for i in range(len(arr) - 1, -1, -1):
            if arr[i] == 0xFF:
                arr[i] = 0
            else:
                arr[i] += 1
                break
        
        return bytes(arr)