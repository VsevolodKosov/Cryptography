"""S-box provider for Rijndael cipher"""

from typing import Optional
from src.galois.galois_field_service import GaloisFieldService
from src.galois.types import IGaloisFieldService
from src.aes_rijndael.types import ISBoxProvider
from src.aes_rijndael.affine_transform import aes_affine_forward, make_aes_affine_inverse


class SBoxProvider:
    """Provider for S-boxes with lazy initialization"""
    
    def __init__(self, gf: GaloisFieldService) -> None:
        self._gf: IGaloisFieldService = gf
        self._sbox: Optional[bytes] = None
        self._invsbox: Optional[bytes] = None
        self._inv_affine_fn = make_aes_affine_inverse()
    
    def get_s_box(self) -> bytes:
        """Get forward S-box (lazy initialization)"""
        if self._sbox is None:
            box = bytearray(256)
            for a in range(256):
                inv = 0 if a == 0 else self._gf.inverse(a)
                box[a] = aes_affine_forward(inv)
            self._sbox = bytes(box)
        return self._sbox
    
    def get_inv_s_box(self) -> bytes:
        """Get inverse S-box (lazy initialization)"""
        if self._invsbox is None:
            box = bytearray(256)
            for b in range(256):
                pre = self._inv_affine_fn(b)
                a = 0 if pre == 0 else self._gf.inverse(pre)
                box[b] = a
            self._invsbox = bytes(box)
        return self._invsbox

