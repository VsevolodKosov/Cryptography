"""State manipulation utilities for Rijndael cipher"""

from typing import Literal


def state_index(r: int, c: int, nb: int) -> int:
    """Get linear index from row and column in state matrix"""
    return c * 4 + r


def state_to_bytes(state: bytearray) -> bytes:
    """Convert state array to bytes"""
    return bytes(state)


def rot_left_row(row: bytearray, shift: int) -> bytearray:
    """Rotate row left by shift positions"""
    n = len(row)
    r = bytearray(n)
    for i in range(n):
        r[i] = row[(i + (shift % n)) % n]
    return r


def rot_right_row(row: bytearray, shift: int) -> bytearray:
    """Rotate row right by shift positions"""
    n = len(row)
    r = bytearray(n)
    for i in range(n):
        r[i] = row[(i + n - (shift % n)) % n]
    return r


def get_shift_offsets(nb: Literal[4, 6, 8]) -> tuple[int, int, int, int]:
    """Get shift offsets for ShiftRows operation"""
    if nb == 4:
        return (0, 1, 2, 3)
    if nb == 6:
        return (0, 1, 2, 3)
    if nb == 8:
        return (0, 1, 3, 4)
    raise ValueError(f"Unsupported Nb={nb}. Allowed: 4,6,8")

