"""Binary matrix operations for affine transformations"""


def parity8(x: int) -> int:
    """Calculate parity of 8-bit value"""
    x ^= x >> 4
    x ^= x >> 2
    x ^= x >> 1
    return x & 1


def mat_mul_byte(rows: list[int], x: int) -> int:
    """Multiply binary matrix by byte"""
    y = 0
    for i in range(8):
        bit = parity8(rows[i] & x)
        y |= bit << i
    return y & 0xFF


def invert_binary_8x8(rows: list[int]) -> list[int]:
    """Invert 8x8 binary matrix using Gaussian elimination"""
    M = rows.copy()
    I = [1 << i for i in range(8)]
    
    for col in range(8):
        pivot = -1
        for r in range(col, 8):
            if ((M[r] >> col) & 1) == 1:
                pivot = r
                break
        
        if pivot == -1:
            raise ValueError("Affine matrix not invertible.")
        
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]
            I[col], I[pivot] = I[pivot], I[col]
        
        for r in range(8):
            if r != col and ((M[r] >> col) & 1) == 1:
                M[r] ^= M[col]
                I[r] ^= I[col]
    
    return I

