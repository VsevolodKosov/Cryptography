"""Rijndael cipher implementation"""

from typing import Literal, Optional
from src.galois.galois_field_service import GaloisFieldService
from src.galois.types import IGaloisFieldService
from src.aes_rijndael.s_box import SBoxProvider
from src.aes_rijndael.key_expansion import KeyExpansion
from src.aes_rijndael.transformations import Transformations
from src.aes_rijndael.types import (
    IBlockCipher, 
    IKeyExpansion, 
    IRoundTransformations, 
    ISBoxProvider, 
    RijndaelOptions, 
    RoundKeys
)
from src.utils.state_utils import state_index, state_to_bytes, get_shift_offsets


class RijndaelCipher:
    """Rijndael cipher with support for 128/192/256 bit blocks and keys"""
    
    def __init__(self, opts: RijndaelOptions) -> None:
        self._nb: Literal[4, 6, 8] = opts["nb"]
        self._gf: IGaloisFieldService = opts["gf"]
        
        # Get or create S-box provider
        if "sbox_provider" in opts and opts["sbox_provider"] is not None:
            self._sboxes: ISBoxProvider = opts["sbox_provider"]
        else:
            # Ensure gf is GaloisFieldService for SBoxProvider
            if isinstance(opts["gf"], GaloisFieldService):
                self._sboxes = SBoxProvider(opts["gf"])
            else:
                gf_service = GaloisFieldService()
                self._sboxes = SBoxProvider(gf_service)
        
        self._strict_sizes: bool = opts.get("strict_sizes", False) or False
        
        # Ensure sboxes is SBoxProvider for KeyExpansion and Transformations
        if isinstance(self._sboxes, SBoxProvider):
            sbox_provider = self._sboxes
        else:
            gf_for_sbox = self._gf if isinstance(self._gf, GaloisFieldService) else GaloisFieldService()
            sbox_provider = SBoxProvider(gf_for_sbox)
        
        self._key_expansion: IKeyExpansion = KeyExpansion(self._gf, sbox_provider)
        self._transformations: IRoundTransformations = Transformations(self._gf, sbox_provider, self._nb)
        self._rk: Optional[RoundKeys] = None
    
    def get_block_size(self) -> int:
        """Get block size in bytes"""
        return self._nb * 4
    
    def expand_key(
        self, 
        key_in: bytes, 
        nk: Literal[4, 6, 8] | None = None
    ) -> RoundKeys:
        """Expand key into round keys"""
        rk = self._key_expansion.expand_key(
            key_in, 
            self._nb, 
            nk, 
            self._strict_sizes
        )
        self._rk = rk
        return rk
    
    def set_round_keys(self, rk: RoundKeys) -> None:
        """Set round keys"""
        if rk.nb != self._nb:
            raise ValueError(f"RoundKeys.nb={rk.nb} mismatch with cipher nb={self._nb}")
        self._rk = rk
    
    def encrypt_block(
        self, 
        data: bytes, 
        rk: RoundKeys | None = None
    ) -> bytes:
        """Encrypt a block of data"""
        round_keys = rk or self._rk
        if round_keys is None:
            raise ValueError("Round keys not set. Call expand_key() or set_round_keys().")
        if round_keys.nb != self._nb:
            raise ValueError("Round keys nb mismatch.")
        
        state = bytearray(self._normalize_block_input(data))
        nr = round_keys.nr
        
        self._transformations.add_round_key(state, round_keys, 0)
        
        for round_num in range(1, nr):
            self._transformations.sub_bytes(state)
            self._shift_rows(state)
            self._transformations.mix_columns(state)
            self._transformations.add_round_key(state, round_keys, round_num)
        
        self._transformations.sub_bytes(state)
        self._shift_rows(state)
        self._transformations.add_round_key(state, round_keys, nr)
        
        return state_to_bytes(state)
    
    def decrypt_block(
        self, 
        data: bytes, 
        rk: RoundKeys | None = None
    ) -> bytes:
        """Decrypt a block of data"""
        round_keys = rk or self._rk
        if round_keys is None:
            raise ValueError("Round keys not set. Call expand_key() or set_round_keys().")
        if round_keys.nb != self._nb:
            raise ValueError("Round keys nb mismatch.")
        
        state = bytearray(self._normalize_block_input(data))
        nr = round_keys.nr
        
        self._transformations.add_round_key(state, round_keys, nr)
        
        for round_num in range(nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._transformations.inv_sub_bytes(state)
            self._transformations.add_round_key(state, round_keys, round_num)
            self._transformations.inv_mix_columns(state)
        
        self._inv_shift_rows(state)
        self._transformations.inv_sub_bytes(state)
        self._transformations.add_round_key(state, round_keys, 0)
        
        return state_to_bytes(state)
    
    def _normalize_block_input(self, input_data: bytes) -> bytes:
        """Normalize block input to expected size"""
        expected = self._nb * 4
        if len(input_data) == expected:
            return input_data
        if self._strict_sizes:
            raise ValueError(f"Invalid block size {len(input_data)}, expected {expected}")
        if len(input_data) < expected:
            raise ValueError(f"Invalid block size {len(input_data)}, expected {expected}")
        return input_data[:expected]
    
    def _shift_rows(self, state: bytearray) -> None:
        """Apply ShiftRows transformation"""
        nb = self._nb
        shifts = get_shift_offsets(nb)
        for r in range(1, 4):
            row = bytearray(nb)
            for c in range(nb):
                row[c] = state[state_index(r, c, nb)]
            # Rotate left
            n = len(row)
            rotated = bytearray(n)
            for i in range(n):
                rotated[i] = row[(i + (shifts[r] % n)) % n]
            for c in range(nb):
                state[state_index(r, c, nb)] = rotated[c]
    
    def _inv_shift_rows(self, state: bytearray) -> None:
        """Apply inverse ShiftRows transformation"""
        nb = self._nb
        shifts = get_shift_offsets(nb)
        for r in range(1, 4):
            row = bytearray(nb)
            for c in range(nb):
                row[c] = state[state_index(r, c, nb)]
            # Rotate right
            n = len(row)
            rotated = bytearray(n)
            for i in range(n):
                rotated[i] = row[(i + n - (shifts[r] % n)) % n]
            for c in range(nb):
                state[state_index(r, c, nb)] = rotated[c]

