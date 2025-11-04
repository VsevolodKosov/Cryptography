from typing import Optional
from src.cipher.interface import RSAKeyPair, RSAPublicKey, RSAKeyGeneratorConfig
from src.cipher.key_generation import RSAKeyGenerator
from src.utils.cipher_service import CipherService


class RSACryptoService:
    def __init__(self, config: RSAKeyGeneratorConfig):
        self.key_pair: Optional[RSAKeyPair] = None
        self.key_generator = RSAKeyGenerator(config)
    
    async def generate_key_pair(self) -> None:
        self.key_pair = await self.key_generator.generate_key_pair()
    
    async def generate_weak_key_pair(self) -> None:
        self.key_pair = await self.key_generator.generate_weak_key_pair()
    
    async def generate_weak_key_pair_for_fermat(self) -> None:
        self.key_pair = await self.key_generator.generate_weak_key_pair_for_fermat()
    
    def encrypt(self, data: int) -> int:
        if not self.key_pair:
            raise ValueError("Пара ключей не сгенерирована")
        
        modulus = self.key_pair['public_key']['modulus']
        exponent = self.key_pair['public_key']['exponent']
        
        if data >= modulus:
            raise ValueError("Данные должны быть меньше модуля")
        
        if data == 1 or CipherService.gcd(data, modulus) != 1:
            raise ValueError("Данные должны быть взаимно просты с модулем и не равны 1")
        
        return CipherService.mod_pow(data, exponent, modulus)
    
    def decrypt(self, data: int) -> int:
        if not self.key_pair:
            raise ValueError("Пара ключей не сгенерирована")
        
        modulus = self.key_pair['private_key']['modulus']
        exponent = self.key_pair['private_key']['exponent']
        
        if data >= modulus:
            raise ValueError("Данные должны быть меньше модуля")
        
        return CipherService.mod_pow(data, exponent, modulus)
    
    def get_public_key(self) -> Optional[RSAPublicKey]:
        return self.key_pair['public_key'] if self.key_pair else None
    
    def set_public_key(self, public_key: RSAPublicKey) -> None:
        if not self.key_pair:
            self.key_pair = {
                'public_key': public_key,
                'private_key': {'exponent': 0, 'modulus': 0}  # Заглушка
            }
        else:
            self.key_pair['public_key'] = public_key
    
    def get_private_key(self) -> Optional[dict]:
        return self.key_pair['private_key'] if self.key_pair else None