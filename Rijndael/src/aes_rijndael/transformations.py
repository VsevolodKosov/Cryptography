"""Round transformations for Rijndael cipher"""

from typing import Literal
from src.galois.types import IGaloisFieldService
from src.aes_rijndael.types import IRoundTransformations, ISBoxProvider, RoundKeys
from src.utils.state_utils import state_index, get_shift_offsets


class Transformations:
    """Round transformations implementation"""
    
    def __init__(
        self, 
        gf: IGaloisFieldService, 
        sboxes: ISBoxProvider, 
        nb: Literal[4, 6, 8]
    ) -> None:
        self._gf = gf
        self._sboxes = sboxes
        self._nb = nb
    
    def sub_bytes(self, state: bytearray) -> None:
        """Apply SubBytes transformation"""
        sbox = self._sboxes.get_s_box()
        for i in range(len(state)):
            state[i] = sbox[state[i]]
    
    def inv_sub_bytes(self, state: bytearray) -> None:
        """Apply inverse SubBytes transformation"""
        invs = self._sboxes.get_inv_s_box()
        for i in range(len(state)):
            state[i] = invs[state[i]]
    
    def shift_rows(self, state: bytearray) -> None:
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
    
    def inv_shift_rows(self, state: bytearray) -> None:
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
    
    def mix_columns(self, state: bytearray) -> None:
        """Apply MixColumns transformation"""
        nb = self._nb
        for c in range(nb):
            a0 = state[state_index(0, c, nb)]
            a1 = state[state_index(1, c, nb)]
            a2 = state[state_index(2, c, nb)]
            a3 = state[state_index(3, c, nb)]
            r0 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x02, a0),
                        self._gf.multiply(0x03, a1)
                    ),
                    a2
                ),
                a3
            )
            r1 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        a0,
                        self._gf.multiply(0x02, a1)
                    ),
                    self._gf.multiply(0x03, a2)
                ),
                a3
            )
            r2 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        a0,
                        a1
                    ),
                    self._gf.multiply(0x02, a2)
                ),
                self._gf.multiply(0x03, a3)
            )
            r3 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x03, a0),
                        a1
                    ),
                    a2
                ),
                self._gf.multiply(0x02, a3)
            )
            state[state_index(0, c, nb)] = r0
            state[state_index(1, c, nb)] = r1
            state[state_index(2, c, nb)] = r2
            state[state_index(3, c, nb)] = r3
    
    def inv_mix_columns(self, state: bytearray) -> None:
        """Apply inverse MixColumns transformation"""
        nb = self._nb
        for c in range(nb):
            a0 = state[state_index(0, c, nb)]
            a1 = state[state_index(1, c, nb)]
            a2 = state[state_index(2, c, nb)]
            a3 = state[state_index(3, c, nb)]
            r0 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x0E, a0),
                        self._gf.multiply(0x0B, a1)
                    ),
                    self._gf.multiply(0x0D, a2)
                ),
                self._gf.multiply(0x09, a3)
            )
            r1 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x09, a0),
                        self._gf.multiply(0x0E, a1)
                    ),
                    self._gf.multiply(0x0B, a2)
                ),
                self._gf.multiply(0x0D, a3)
            )
            r2 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x0D, a0),
                        self._gf.multiply(0x09, a1)
                    ),
                    self._gf.multiply(0x0E, a2)
                ),
                self._gf.multiply(0x0B, a3)
            )
            r3 = self._gf.add(
                self._gf.add(
                    self._gf.add(
                        self._gf.multiply(0x0B, a0),
                        self._gf.multiply(0x0D, a1)
                    ),
                    self._gf.multiply(0x09, a2)
                ),
                self._gf.multiply(0x0E, a3)
            )
            state[state_index(0, c, nb)] = r0
            state[state_index(1, c, nb)] = r1
            state[state_index(2, c, nb)] = r2
            state[state_index(3, c, nb)] = r3
    
    def add_round_key(self, state: bytearray, rk: RoundKeys, round: int) -> None:
        """Apply AddRoundKey transformation"""
        nb = rk.nb
        for c in range(nb):
            base = (round * nb + c) * 4
            state[state_index(0, c, nb)] = self._gf.add(
                state[state_index(0, c, nb)], 
                rk.bytes[base]
            )
            state[state_index(1, c, nb)] = self._gf.add(
                state[state_index(1, c, nb)], 
                rk.bytes[base + 1]
            )
            state[state_index(2, c, nb)] = self._gf.add(
                state[state_index(2, c, nb)], 
                rk.bytes[base + 2]
            )
            state[state_index(3, c, nb)] = self._gf.add(
                state[state_index(3, c, nb)], 
                rk.bytes[base + 3]
            )

