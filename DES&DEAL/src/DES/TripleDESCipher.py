from src.DES.DESCipher import DESCipher
from src.interfaces import ISymmetricCipher
import asyncio


class TripleDESCipher(ISymmetricCipher):
    """Triple DES implementation using EDE (Encrypt-Decrypt-Encrypt) mode"""
    
    def __init__(self, key: bytes = None):
        if key is not None:
            if len(key) not in (16, 24):
                raise ValueError("TripleDES key must be 16 or 24 bytes, got %d" % len(key))
        
        self._key = key
        self._c1 = DESCipher()
        self._c2 = DESCipher()
        self._c3 = DESCipher()
        
        if key is not None:
            self._set_keys(key)
    
    @property
    def block_size(self) -> int:
        return 8
    
    def set_key(self, key: bytes) -> None:
        """Set key for TripleDES"""
        if len(key) not in (16, 24):
            raise ValueError("TripleDES key must be 16 or 24 bytes, got %d" % len(key))
        
        self._key = key
        self._set_keys(key)
    
    def _set_keys(self, key: bytes) -> None:
        """Set keys for all three DES instances"""
        if len(key) not in (16, 24):
            raise ValueError("TripleDES key must be 16 or 24 bytes, got %d" % len(key))
        
        k1 = key[0:8]
        k2 = key[8:16]
        
        if len(key) == 16:
            k3 = k1
        else:
            k3 = key[16:24]
        
        key_expansion = self._c1.key_expansion
        self._c1.set_round_keys(key_expansion.generate_round_keys(k1))
        self._c2.set_round_keys(key_expansion.generate_round_keys(k2))
        self._c3.set_round_keys(key_expansion.generate_round_keys(k3))
    
    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt block using EDE (Encrypt-Decrypt-Encrypt)"""
        if len(block) != 8:
            raise ValueError("block size must be 8 bytes, got %d" % len(block))
        
        if self._key is None:
            raise ValueError("Key not set")
        
        b1 = self._c1.encrypt_block(block)
        b2 = self._c2.decrypt_block(b1)
        b3 = self._c3.encrypt_block(b2)
        
        return b3
    
    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt block using DED (Decrypt-Encrypt-Decrypt)"""
        if len(block) != 8:
            raise ValueError("block size must be 8 bytes, got %d" % len(block))
        
        if self._key is None:
            raise ValueError("Key not set")
        
        b1 = self._c3.decrypt_block(block)
        b2 = self._c2.encrypt_block(b1)
        b3 = self._c1.decrypt_block(b2)
        
        return b3
    
    async def encrypt_block_async(self, block: bytes) -> bytes:
        """Async encrypt block"""
        return await asyncio.to_thread(self.encrypt_block, block)
    
    async def decrypt_block_async(self, block: bytes) -> bytes:
        """Async decrypt block"""
        return await asyncio.to_thread(self.decrypt_block, block)

