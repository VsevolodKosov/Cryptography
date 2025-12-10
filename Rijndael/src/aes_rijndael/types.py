"""Type definitions for Rijndael cipher"""

from dataclasses import dataclass
from typing import Protocol, Literal, TypedDict
from src.galois.types import IGaloisFieldService


@dataclass
class RoundKeys:
    """Round keys structure"""
    nb: int
    nk: int
    nr: int
    bytes: bytes


class RijndaelOptionsRequired(TypedDict):
    """Required options for Rijndael cipher initialization"""
    nb: Literal[4, 6, 8]
    gf: IGaloisFieldService


class RijndaelOptions(RijndaelOptionsRequired, total=False):
    """Options for Rijndael cipher initialization"""
    sbox_provider: 'ISBoxProvider'
    strict_sizes: bool


class IBlockCipher(Protocol):
    """Protocol for block cipher interface"""
    
    def encrypt_block(self, data: bytes, round_keys: RoundKeys | None = None) -> bytes:
        """Encrypt a block of data"""
        ...
    
    def decrypt_block(self, data: bytes, round_keys: RoundKeys | None = None) -> bytes:
        """Decrypt a block of data"""
        ...
    
    def get_block_size(self) -> int:
        """Get block size in bytes"""
        ...
    
    def expand_key(self, key: bytes, nk: Literal[4, 6, 8] | None = None) -> RoundKeys:
        """Expand key into round keys"""
        ...
    
    def set_round_keys(self, round_keys: RoundKeys) -> None:
        """Set round keys"""
        ...


class IKeyExpansion(Protocol):
    """Protocol for key expansion interface"""
    
    def expand_key(
        self, 
        key: bytes, 
        nb: Literal[4, 6, 8], 
        nk: Literal[4, 6, 8] | None = None, 
        strict_sizes: bool = False
    ) -> RoundKeys:
        """Expand key into round keys"""
        ...


class IRoundTransformations(Protocol):
    """Protocol for round transformations interface"""
    
    def sub_bytes(self, state: bytearray) -> None:
        """Apply SubBytes transformation"""
        ...
    
    def inv_sub_bytes(self, state: bytearray) -> None:
        """Apply inverse SubBytes transformation"""
        ...
    
    def shift_rows(self, state: bytearray) -> None:
        """Apply ShiftRows transformation"""
        ...
    
    def inv_shift_rows(self, state: bytearray) -> None:
        """Apply inverse ShiftRows transformation"""
        ...
    
    def mix_columns(self, state: bytearray) -> None:
        """Apply MixColumns transformation"""
        ...
    
    def inv_mix_columns(self, state: bytearray) -> None:
        """Apply inverse MixColumns transformation"""
        ...
    
    def add_round_key(self, state: bytearray, rk: RoundKeys, round: int) -> None:
        """Apply AddRoundKey transformation"""
        ...


class ISBoxProvider(Protocol):
    """Protocol for S-box provider interface"""
    
    def get_s_box(self) -> bytes:
        """Get forward S-box"""
        ...
    
    def get_inv_s_box(self) -> bytes:
        """Get inverse S-box"""
        ...

