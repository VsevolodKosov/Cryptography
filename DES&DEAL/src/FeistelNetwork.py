from src.interfaces import IFeistelNetwork, ISymmetricCipher, IEncryptor, IKeyExpansion
from src.utils.bit_utils import xor_bytes


class FeistelNetwork(IFeistelNetwork, ISymmetricCipher):
    def __init__(
        self,
        key_expansion: IKeyExpansion,
        encryptor: IEncryptor,
        master_key: bytes = None,  
        block_size: int = 8,
        rounds: int = 16
    ):
        self.key_expansion = key_expansion
        self.encryptor = encryptor
        self._block_size = block_size
        self._rounds = rounds
        
        self._validate_parameters()
        
        self.master_key = master_key
        self.round_keys = self.key_expansion.generate_round_keys(master_key) if master_key else []

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def rounds(self) -> int:
        return self._rounds
    
    def _validate_parameters(self):
        if self._block_size <= 0 or self._block_size % 2 != 0:
            raise ValueError('Размер блока должен быть положительным четным числом')
        if self._rounds <= 0:
            raise ValueError('Количество раундов должно быть положительным')

    def _validate_block(self, block: bytes):
        if not isinstance(block, bytes):
            raise TypeError('Блок должен быть байтовым')
        if len(block) != self._block_size:
            raise ValueError(f'Размер блока ожидается как {self._block_size} {len(block)} байт')
    
    def generate_round_keys(self, master_key: bytes) -> list:
        return self.key_expansion.generate_round_keys(master_key)
    
    def _process_block(self, block: bytes, round_keys: list, reverse: bool = False) -> bytes:
        keys = list(reversed(round_keys)) if reverse else round_keys
        
        half_size = self._block_size // 2
        L = block[:half_size]
        R = block[half_size:]

        for i in range(self._rounds):
            new_L = R
            f_result = self.encryptor.Feistel_function(R, keys[i])
            new_R = xor_bytes(L, f_result)
            L, R = new_L, new_R

        return R + L

    def encrypt_block(self, block: bytes, master_key: bytes = None) -> bytes:
        self._validate_block(block)
        
        if master_key is not None:
            round_keys = self.key_expansion.generate_round_keys(master_key)
        elif self.round_keys:
            round_keys = self.round_keys
        else:
            raise ValueError("Не установлен мастер-ключ или раундовые ключи")
        
        
        result = self._process_block(block, round_keys, reverse=False)
        return result

    def decrypt_block(self, block: bytes, master_key: bytes = None) -> bytes:
        self._validate_block(block)
        
        if master_key is not None:
            round_keys = self.key_expansion.generate_round_keys(master_key)
        elif self.round_keys:
            round_keys = self.round_keys
        else:
            raise ValueError("Не установлен мастер-ключ или раундовые ключи")
        
        result = self._process_block(block, round_keys, reverse=True)
        return result

    def set_round_keys(self, round_keys: list):
        if not isinstance(round_keys, list):
            raise TypeError(f"round_keys должен быть list, получен {type(round_keys)}")
        if len(round_keys) != self.rounds:
            raise ValueError(f"Требуется {self._rounds} раундовых ключей, получено {len(round_keys)}")
    
        self.round_keys = round_keys.copy()
        self.master_key = None  


