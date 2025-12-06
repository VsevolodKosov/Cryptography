from typing import Optional
from src.cipher.interface import RSAPublicKey, RSAKeyGeneratorConfig
from src.cipher.key_generation import RSAKeyGenerator
from src.utils.cipher_service import CipherService

class RSACryptoService:
    def __init__(self, config: RSAKeyGeneratorConfig):
        self.key_generator = RSAKeyGenerator(config)
        self.key_pair = self.key_generator.generate_key_pair()
    
    def generate_key_pair(self) -> None:
        self.key_pair = self.key_generator.generate_key_pair()
    
    def generate_weak_key_pair(self) -> None:
        self.key_pair = self.key_generator.generate_weak_key_pair()
    
    def generate_weak_key_pair_for_fermat(self) -> None:
        self.key_pair = self.key_generator.generate_weak_key_pair_for_fermat()
    
    def encrypt(self, data: int) -> int:
        if not self.key_pair:
            raise ValueError("Пара ключей не сгенерирована")
        
        modulus = self.key_pair['public_key']['modulus']
        exponent = self.key_pair['public_key']['exponent']
        
        return CipherService.mod_pow(data, exponent, modulus)
    
    def decrypt(self, data: int) -> int:
        if not self.key_pair:
            raise ValueError("Пара ключей не сгенерирована")
        
        modulus = self.key_pair['private_key']['modulus']
        exponent = self.key_pair['private_key']['exponent']
        
        return CipherService.mod_pow(data, exponent, modulus)
    
    def get_public_key(self) -> Optional[RSAPublicKey]:
        return self.key_pair['public_key'] 
    
    def set_public_key(self, public_key: RSAPublicKey) -> None:
        self.key_pair['public_key'] = public_key
    
    def get_private_key(self) -> Optional[dict]:
        return self.key_pair['private_key'] 