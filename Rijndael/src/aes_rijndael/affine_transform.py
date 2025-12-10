"""Affine transformations for AES S-box generation"""

from src.utils.binary_matrix_utils import invert_binary_8x8, mat_mul_byte


def aes_affine_forward(x: int) -> int:
    """Apply AES forward affine transformation"""
    x &= 0xFF
    y = 0
    for i in range(8):
        bit = (
            ((x >> i) & 1) ^
            ((x >> ((i + 4) & 7)) & 1) ^
            ((x >> ((i + 5) & 7)) & 1) ^
            ((x >> ((i + 6) & 7)) & 1) ^
            ((x >> ((i + 7) & 7)) & 1) ^
            ((0x63 >> i) & 1)
        )
        y |= bit << i
    return y & 0xFF


def _make_aes_affine_m() -> list[int]:
    """Create AES affine matrix M"""
    rows: list[int] = [0] * 8
    for i in range(8):
        row = 0
        for j in [i, (i + 4) & 7, (i + 5) & 7, (i + 6) & 7, (i + 7) & 7]:
            row |= (1 << j)
        rows[i] = row & 0xFF
    return rows


def make_aes_affine_inverse():
    """Create AES inverse affine transformation function"""
    M = _make_aes_affine_m()
    Minv = invert_binary_8x8(M)
    
    def inv_transform(b: int) -> int:
        b &= 0xFF
        u = b ^ 0x63
        return mat_mul_byte(Minv, u)
    
    return inv_transform

