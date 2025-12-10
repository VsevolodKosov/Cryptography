"""Key expansion for Rijndael cipher"""

from typing import Literal
from src.galois.types import IGaloisFieldService
from src.aes_rijndael.types import IKeyExpansion, ISBoxProvider, RoundKeys


class KeyExpansion:
    """Key expansion implementation"""
    
    def __init__(self, gf: IGaloisFieldService, sboxes: ISBoxProvider) -> None:
        self._gf = gf
        self._sboxes = sboxes
    
    def _generate_rcon(self, count: int) -> bytes:
        """Generate round constants"""
        rcon = bytearray(count * 4)
        rc = 0x01
        for i in range(1, count):
            rcon[i * 4] = rc
            rcon[i * 4 + 1] = 0x00
            rcon[i * 4 + 2] = 0x00
            rcon[i * 4 + 3] = 0x00
            rc = self._gf.multiply(rc, 0x02)
        return bytes(rcon)
    
    def _sub_word(self, word: int, sbox: bytes) -> int:
        """Substitute word using S-box"""
        b0 = sbox[(word >> 24) & 0xFF]
        b1 = sbox[(word >> 16) & 0xFF]
        b2 = sbox[(word >> 8) & 0xFF]
        b3 = sbox[word & 0xFF]
        return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF
    
    def _rot_word(self, word: int) -> int:
        """Rotate word left by one byte"""
        return ((word << 8) | ((word >> 24) & 0xFF)) & 0xFFFFFFFF
    
    def _normalize_key_if_needed(
        self, 
        key: bytes, 
        strict_sizes: bool
    ) -> bytes:
        """Normalize key length if needed"""
        if strict_sizes:
            return key
        
        allowed = (16, 24, 32)
        if len(key) in allowed:
            return key
        
        best: Literal[16, 24, 32] = 16
        best_diff = abs(len(key) - 16)
        for s in (24, 32):
            d = abs(len(key) - s)
            if d < best_diff:
                best_diff = d
                best = s  # type: ignore
        
        if best_diff > 1:
            return key
        
        if len(key) < best:
            out = bytearray(best)
            out[:len(key)] = key
            return bytes(out)
        else:
            return key[:best]
    
    def expand_key(
        self, 
        key_in: bytes, 
        nb: Literal[4, 6, 8], 
        nk: Literal[4, 6, 8] | None = None, 
        strict_sizes: bool = False
    ) -> RoundKeys:
        """Expand key into round keys"""
        key = self._normalize_key_if_needed(key_in, strict_sizes)
        
        # Infer nk from key length
        key_len = len(key)
        if key_len == 16:
            inferred_nk: Literal[4, 6, 8] = 4
        elif key_len == 24:
            inferred_nk = 6
        elif key_len == 32:
            inferred_nk = 8
        else:
            raise ValueError(f"Invalid key length {key_len}. Expected 16/24/32")
        
        if nk is None:
            nk = inferred_nk
        else:
            nk = inferred_nk
        
        nr = max(nb, nk) + 6
        
        total_words = (nr + 1) * nb
        w = [0] * total_words
        
        # Copy initial key into w
        for i in range(nk):
            base = 4 * i
            w[i] = (
                (key[base] << 24) |
                (key[base + 1] << 16) |
                (key[base + 2] << 8) |
                key[base + 3]
            ) & 0xFFFFFFFF
        
        sbox = self._sboxes.get_s_box()
        rcon = self._generate_rcon((total_words // nk) + 1)
        
        # Generate remaining words
        for i in range(nk, total_words):
            temp = w[i - 1] & 0xFFFFFFFF
            
            if i % nk == 0:
                rc = (rcon[(i // nk) * 4] << 24) & 0xFFFFFFFF
                temp = (self._sub_word(self._rot_word(temp), sbox) ^ rc) & 0xFFFFFFFF
            elif nk == 8 and (i % nk) == 4:
                temp = self._sub_word(temp, sbox) & 0xFFFFFFFF
            
            w[i] = (w[i - nk] ^ temp) & 0xFFFFFFFF
        
        # Convert words to bytes
        rk_bytes = bytearray(total_words * 4)
        for i in range(total_words):
            word = w[i] & 0xFFFFFFFF
            offs = i * 4
            rk_bytes[offs] = (word >> 24) & 0xFF
            rk_bytes[offs + 1] = (word >> 16) & 0xFF
            rk_bytes[offs + 2] = (word >> 8) & 0xFF
            rk_bytes[offs + 3] = word & 0xFF
        
        return RoundKeys(nb=nb, nk=nk, nr=nr, bytes=bytes(rk_bytes))

