"""Crypto context for cipher modes and padding"""

from typing import Optional
from src.modes.constants import CipherMode, PaddingMode
from src.aes_rijndael.types import IBlockCipher
from src.utils.modes_utils import split_blocks, join_blocks, xor_bytes, random_bytes


class CryptoContext:
    """Context for encryption/decryption with various modes and padding"""
    
    def __init__(
        self,
        cipher: IBlockCipher,
        mode: CipherMode,
        padding: PaddingMode,
        iv: Optional[bytes] = None
    ) -> None:
        self.cipher = cipher
        self.mode = mode
        self.padding = padding
        self.iv = iv
        self._block_size = cipher.get_block_size()
        self._validate_parameters()
    
    def _validate_parameters(self) -> None:
        """Validate initialization parameters"""
        if self.mode not in (CipherMode.ECB, CipherMode.CTR):
            if self.iv is None:
                raise ValueError(f"IV is required for {self.mode.value} mode")
            if len(self.iv) != self._block_size:
                raise ValueError(
                    f"IV length must be {self._block_size} bytes, got {len(self.iv)}"
                )
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with configured mode and padding"""
        padded_data = self._pad(data, self.padding)
        blocks = split_blocks(padded_data, self._block_size)
        encrypted_blocks = self._encrypt_blocks(blocks)
        return join_blocks(encrypted_blocks)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with configured mode and padding"""
        blocks = split_blocks(data, self._block_size)
        decrypted_blocks = self._decrypt_blocks(blocks)
        decrypted_data = join_blocks(decrypted_blocks)
        return self._unpad(decrypted_data, self.padding)
    
    def _encrypt_blocks(self, blocks: list[bytes]) -> list[bytes]:
        """Encrypt blocks based on mode"""
        if self.mode == CipherMode.ECB:
            return self._encrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self._encrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self._encrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self._encrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self._encrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self._encrypt_ctr(blocks)
        elif self.mode == CipherMode.RandomDelta:
            return self._encrypt_random_delta(blocks)
        else:
            raise ValueError(f"Unsupported encryption mode: {self.mode}")
    
    def _decrypt_blocks(self, blocks: list[bytes]) -> list[bytes]:
        """Decrypt blocks based on mode"""
        if self.mode == CipherMode.ECB:
            return self._decrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self._decrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self._decrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self._decrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self._decrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self._decrypt_ctr(blocks)
        elif self.mode == CipherMode.RandomDelta:
            return self._decrypt_random_delta(blocks)
        else:
            raise ValueError(f"Unsupported decryption mode: {self.mode}")
    
    def _encrypt_ecb(self, blocks: list[bytes]) -> list[bytes]:
        """ECB mode encryption"""
        return [self.cipher.encrypt_block(block) for block in blocks]
    
    def _decrypt_ecb(self, blocks: list[bytes]) -> list[bytes]:
        """ECB mode decryption"""
        return [self.cipher.decrypt_block(block) for block in blocks]
    
    def _encrypt_cbc(self, blocks: list[bytes]) -> list[bytes]:
        """CBC mode encryption"""
        result: list[bytes] = []
        previous_block = self.iv  # type: ignore
        
        for block in blocks:
            xored = xor_bytes(block, previous_block)
            encrypted = self.cipher.encrypt_block(xored)
            result.append(encrypted)
            previous_block = encrypted
        
        return result
    
    def _decrypt_cbc(self, blocks: list[bytes]) -> list[bytes]:
        """CBC mode decryption"""
        result: list[bytes] = []
        previous_block = self.iv  # type: ignore
        
        for block in blocks:
            decrypted = self.cipher.decrypt_block(block)
            plaintext = xor_bytes(decrypted, previous_block)
            result.append(plaintext)
            previous_block = block
        
        return result
    
    def _encrypt_pcbc(self, blocks: list[bytes]) -> list[bytes]:
        """PCBC mode encryption"""
        result: list[bytes] = []
        feedback = self.iv  # type: ignore
        
        for block in blocks:
            xored = xor_bytes(block, feedback)
            encrypted = self.cipher.encrypt_block(xored)
            result.append(encrypted)
            feedback = xor_bytes(block, encrypted)
        
        return result
    
    def _decrypt_pcbc(self, blocks: list[bytes]) -> list[bytes]:
        """PCBC mode decryption"""
        result: list[bytes] = []
        feedback = self.iv  # type: ignore
        
        for block in blocks:
            decrypted = self.cipher.decrypt_block(block)
            plaintext = xor_bytes(decrypted, feedback)
            result.append(plaintext)
            feedback = xor_bytes(plaintext, block)
        
        return result
    
    def _encrypt_cfb(self, blocks: list[bytes]) -> list[bytes]:
        """CFB mode encryption"""
        result: list[bytes] = []
        shift_register = self.iv  # type: ignore
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(shift_register)
            
            effective_keystream = (
                keystream if len(block) == self._block_size 
                else keystream[:len(block)]
            )
            
            encrypted = xor_bytes(block, effective_keystream)
            result.append(encrypted)
            
            if len(encrypted) == self._block_size:
                shift_register = encrypted
            else:
                new_shift_register = bytearray(self._block_size)
                new_shift_register[:len(encrypted)] = encrypted
                shift_register = bytes(new_shift_register)
        
        return result
    
    def _decrypt_cfb(self, blocks: list[bytes]) -> list[bytes]:
        """CFB mode decryption"""
        result: list[bytes] = []
        shift_register = self.iv  # type: ignore
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(shift_register)
            
            effective_keystream = (
                keystream if len(block) == self._block_size 
                else keystream[:len(block)]
            )
            
            decrypted = xor_bytes(block, effective_keystream)
            result.append(decrypted)
            
            if len(block) == self._block_size:
                shift_register = block
            else:
                new_shift_register = bytearray(self._block_size)
                new_shift_register[:len(block)] = block
                shift_register = bytes(new_shift_register)
        
        return result
    
    def _encrypt_ofb(self, blocks: list[bytes]) -> list[bytes]:
        """OFB mode encryption"""
        result: list[bytes] = []
        keystream = self.iv  # type: ignore
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(keystream)
            
            effective_keystream = (
                keystream if len(block) == self._block_size 
                else keystream[:len(block)]
            )
            
            result.append(xor_bytes(block, effective_keystream))
        
        return result
    
    def _decrypt_ofb(self, blocks: list[bytes]) -> list[bytes]:
        """OFB mode decryption (same as encryption)"""
        return self._encrypt_ofb(blocks)
    
    def _encrypt_ctr(self, blocks: list[bytes]) -> list[bytes]:
        """CTR mode encryption"""
        result: list[bytes] = []
        counter = (
            bytearray(self.iv) if self.iv 
            else bytearray(self._block_size)
        )
        
        for block in blocks:
            keystream = self.cipher.encrypt_block(bytes(counter))
            
            effective_keystream = (
                keystream if len(block) == self._block_size 
                else keystream[:len(block)]
            )
            
            result.append(xor_bytes(block, effective_keystream))
            counter = self._increment_counter(counter)
        
        return result
    
    def _decrypt_ctr(self, blocks: list[bytes]) -> list[bytes]:
        """CTR mode decryption (same as encryption)"""
        return self._encrypt_ctr(blocks)
    
    def _encrypt_random_delta(self, blocks: list[bytes]) -> list[bytes]:
        """RandomDelta mode encryption"""
        result: list[bytes] = []
        counter = (
            bytearray(self.iv) if self.iv 
            else bytearray(self._block_size)
        )
        
        for block in blocks:
            delta = self._generate_delta(bytes(counter))
            modified_counter = xor_bytes(bytes(counter), delta)
            keystream = self.cipher.encrypt_block(modified_counter)
            
            effective_keystream = (
                keystream if len(block) == self._block_size 
                else keystream[:len(block)]
            )
            
            result.append(xor_bytes(block, effective_keystream))
            counter = self._increment_counter(counter)
        
        return result
    
    def _decrypt_random_delta(self, blocks: list[bytes]) -> list[bytes]:
        """RandomDelta mode decryption (same as encryption)"""
        return self._encrypt_random_delta(blocks)
    
    def _pad(self, data: bytes, mode: PaddingMode) -> bytes:
        """Pad data according to padding mode"""
        if mode == PaddingMode.NONE:
            return data
        
        block_size = self._block_size
        pad_len = block_size - (len(data) % block_size)
        # For PKCS7, ANSI_X923, ISO_10126: always add padding, even if data is multiple of block_size
        # For Zeros: only pad if needed
        if mode == PaddingMode.Zeros:
            if pad_len == block_size:
                return data
            total_length = len(data) + pad_len
        else:
            # PKCS7, ANSI_X923, ISO_10126 always add padding
            total_length = len(data) + pad_len
        
        result = bytearray(total_length)
        result[:len(data)] = data
        
        if mode == PaddingMode.Zeros:
            pass  # Already zero-filled
        elif mode == PaddingMode.ANSI_X923:
            # Fill with zeros, last byte is pad length
            result[total_length - 1] = pad_len
        elif mode == PaddingMode.PKCS7:
            # Fill with pad length
            for i in range(len(data), total_length):
                result[i] = pad_len
        elif mode == PaddingMode.ISO_10126:
            # Fill with random bytes, last byte is pad length
            random_pad = random_bytes(pad_len - 1)
            result[len(data):len(data) + pad_len - 1] = random_pad
            result[total_length - 1] = pad_len
        
        return bytes(result)
    
    def _unpad(self, data: bytes, mode: PaddingMode) -> bytes:
        """Unpad data according to padding mode"""
        if mode == PaddingMode.NONE or len(data) == 0:
            return data
        
        if mode == PaddingMode.Zeros:
            end_index = len(data)
            while end_index > 0 and data[end_index - 1] == 0:
                end_index -= 1
            return data[:end_index]
        
        elif mode in (PaddingMode.ANSI_X923, PaddingMode.PKCS7, PaddingMode.ISO_10126):
            pad_len = data[len(data) - 1]
            if pad_len == 0 or pad_len > len(data) or pad_len > self._block_size:
                raise ValueError(f"Invalid padding length: {pad_len}")
            
            if mode == PaddingMode.PKCS7:
                # Verify all padding bytes are equal to pad_len
                for i in range(len(data) - pad_len, len(data)):
                    if data[i] != pad_len:
                        raise ValueError("Invalid PKCS7 padding")
            elif mode == PaddingMode.ANSI_X923:
                # Verify all padding bytes except last are zero
                for i in range(len(data) - pad_len, len(data) - 1):
                    if data[i] != 0:
                        raise ValueError("Invalid ANSI X.923 padding")
            
            return data[:len(data) - pad_len]
        
        return data
    
    def _increment_counter(self, counter: bytearray) -> bytearray:
        """Increment counter (big-endian)"""
        result = bytearray(counter)
        
        for i in range(len(result) - 1, -1, -1):
            if result[i] == 255:
                result[i] = 0
            else:
                result[i] += 1
                break
        
        return result
    
    def _generate_delta(self, counter: bytes) -> bytes:
        """Generate delta for RandomDelta mode"""
        delta = bytearray(self._block_size)
        
        for i in range(self._block_size):
            delta[i] = (counter[i] * 17 + i * 13) % 256
        
        return bytes(delta)

