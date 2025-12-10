"""Utility functions for cipher modes"""

import secrets
from typing import Union


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    """Split data into blocks of specified size"""
    blocks: list[bytes] = []
    for i in range(0, len(data), block_size):
        block = data[i:min(i + block_size, len(data))]
        blocks.append(block)
    return blocks


def join_blocks(blocks: list[bytes]) -> bytes:
    """Join blocks into single byte string"""
    return b''.join(blocks)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    if len(a) != len(b):
        raise ValueError('Arrays must have same length for XOR')
    
    return bytes(a[i] ^ b[i] for i in range(len(a)))


def random_bytes(length: int) -> bytes:
    """Generate random bytes"""
    return secrets.token_bytes(length)


def arrays_equal(a: bytes, b: bytes) -> bool:
    """Check if two byte arrays are equal"""
    if len(a) != len(b):
        return False
    return a == b


def string_to_bytes(s: str) -> bytes:
    """Convert string to bytes using UTF-8 encoding"""
    return s.encode('utf-8')


def bytes_to_string(b: bytes) -> str:
    """Convert bytes to string using UTF-8 decoding"""
    return b.decode('utf-8')


def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hexadecimal string"""
    return b.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hexadecimal string to bytes"""
    clean = hex_str.replace(' ', '').replace('0x', '').replace('0X', '')
    if len(clean) % 2 != 0:
        raise ValueError('hex length must be even')
    return bytes.fromhex(clean)

