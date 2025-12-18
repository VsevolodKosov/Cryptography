from src.galois.types import IGaloisFieldService
from src.aes_rijndael.types import ISBoxProvider, RoundKeys

class KeyExpansion:    
    def __init__(self, gf: IGaloisFieldService, sboxes: ISBoxProvider) -> None:
        self._gf = gf
        self._sboxes = sboxes
    
    def _generate_rcon(self, count: int) -> bytes:
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
        b0 = sbox[(word >> 24) & 0xFF]
        b1 = sbox[(word >> 16) & 0xFF]
        b2 = sbox[(word >> 8) & 0xFF]
        b3 = sbox[word & 0xFF]
        return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xFFFFFFFF
    
    def _rot_word(self, word: int) -> int:
        return ((word << 8) | ((word >> 24) & 0xFF)) & 0xFFFFFFFF
    
    def expand_key(self, key: bytes, nb: int):
        key_len = len(key)
        
        if key_len == 16:
            nk = 4
        elif key_len == 24:
            nk = 6
        elif key_len == 32:
            nk = 8
        else:
            raise ValueError(f"Invalid key length {key_len}. Expected 16/24/32")

        nr = max(nb, nk) + 6
        
        total_words = (nr + 1) * nb
        w = [0] * total_words
        
        for i in range(nk):
            base = 4 * i
            w[i] = (
                (key[base] << 24) |
                (key[base + 1] << 16) |
                (key[base + 2] << 8) |
                key[base + 3]
            ) & 0xFFFFFFFF
        
        sbox = self._sboxes.get_s_box()
        rcon = self._generate_rcon(nr + 1)
        
        for i in range(nk, total_words):
            temp = w[i - 1] & 0xFFFFFFFF
            
            if i % nk == 0:
                rc_index = (i // nk) * 4 
                rc_word = (rcon[rc_index] << 24) & 0xFFFFFFFF
                temp = (self._sub_word(self._rot_word(temp), sbox) ^ rc_word) & 0xFFFFFFFF
                
            elif nk == 8 and (i % nk) == 4:
                temp = self._sub_word(temp, sbox) & 0xFFFFFFFF
                
            w[i] = (w[i - nk] ^ temp) & 0xFFFFFFFF
        
        rk_bytes = bytearray(total_words * 4)
        for i in range(total_words):
            word = w[i]
            offs = i * 4
            rk_bytes[offs] = (word >> 24) & 0xFF
            rk_bytes[offs + 1] = (word >> 16) & 0xFF
            rk_bytes[offs + 2] = (word >> 8) & 0xFF
            rk_bytes[offs + 3] = word & 0xFF
            
        return RoundKeys(nb=nb, nk=nk, nr=nr, bytes=bytes(rk_bytes))
