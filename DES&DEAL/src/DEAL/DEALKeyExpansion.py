from typing import List
from src.interfaces import IKeyExpansion
from src.utils.bit_utils import xor_bytes
from src.DES.DESCipher import DESCipher
from src.DES.DESKeyExpansion import DESKeyExpansion


class DEALKeyExpansion(IKeyExpansion):
    def generate_round_keys(self, key_bytes: bytes) -> List[bytes]:
        key_size = len(key_bytes)
        rounds = 6 if key_size == 16 else 8
        
        des = DESCipher()
        des_key_expansion = DESKeyExpansion()
        des_round_keys = des_key_expansion.generate_round_keys(key_bytes[:8])
        des.set_round_keys(des_round_keys)
        
        round_keys = []
        R = bytes(8)
        
        if key_size == 16:
            K2 = key_bytes[8:16]
            for i in range(rounds):
                xored = xor_bytes(K2, R)
                round_key = des.encrypt_block(xored)
                round_keys.append(round_key)
                R = round_key
        elif key_size == 24:
            K2 = key_bytes[8:16]
            K3 = key_bytes[16:24]
            for i in range(rounds):
                K = K2 if i < 6 else K3
                xored = xor_bytes(K, R)
                round_key = des.encrypt_block(xored)
                round_keys.append(round_key)
                R = round_key
        else:
            K2 = key_bytes[8:16]
            K3 = key_bytes[16:24]
            K4 = key_bytes[24:32]
            for i in range(rounds):
                if i % 4 == 0:
                    K = K2
                elif i % 4 == 1:
                    K = K3
                elif i % 4 == 2:
                    K = K4
                else:
                    K = K2
                xored = xor_bytes(K, R)
                round_key = des.encrypt_block(xored)
                round_keys.append(round_key)
                R = round_key
        
        return round_keys