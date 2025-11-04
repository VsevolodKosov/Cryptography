import secrets
import asyncio
from typing import Tuple
from src.cipher.interface import RSAKeyPair, RSAKeyGeneratorConfig, PrimalityTestType
from src.utils.primality.base import PrimalityInterface
from src.utils.primality.Fermat import FermatTest
from src.utils.primality.Solovay_Strassen import SolovayStrassenTest
from src.utils.primality.Miller_Rabin import MillerRabinTest
from src.utils.cipher_service import CipherService
from attacks.attacks_service import AttacksService

class RSAKeyGenerator:
    def __init__(self, config: RSAKeyGeneratorConfig):
        self.config = config
        self.test = self._create_primality_test(config.test_type)
    
    def _create_primality_test(self, test_type: PrimalityTestType) -> PrimalityInterface:
        if test_type == PrimalityTestType.FERMAT:
            return FermatTest()
        elif test_type == PrimalityTestType.SOLOVAY_STRASSEN:
            return SolovayStrassenTest()
        elif test_type == PrimalityTestType.MILLER_RABIN:
            return MillerRabinTest()
        else:
            raise ValueError(f"Неизвестный тип теста: {test_type}")
    
    def _generate_prime_candidate(self) -> int:
        min_val = 1 << (self.config.bit_length - 1)
        max_val = (min_val << 1) - 1
        
        range_size = max_val - min_val + 1
        random_bytes = secrets.token_bytes(256)
        
        result = 0
        for byte in random_bytes:
            result = (result << 8) | byte
        
        candidate = min_val + (result % range_size)
        candidate |= 1
        
        set_mask = 0xFF << (self.config.bit_length - 8)
        candidate |= set_mask
        
        return candidate
    
    async def _generate_prime(self) -> int:
        while True:
            candidate = self._generate_prime_candidate()
            if self.test.is_primary(candidate, self.config.min_probability):
                return candidate
    
    def _is_fermat_attack_resistant(self, p: int, q: int) -> bool:
        n = p * q
        min_diff = AttacksService.sqrt(AttacksService.sqrt(n)) * 2
        diff = abs(p - q)
        return diff > min_diff
    
    def _is_wiener_attack_resistant(self, d: int, n: int) -> bool:
        n_sqrt = AttacksService.sqrt(AttacksService.sqrt(n))
        return d * 3 > n_sqrt
    
    async def _generate_prime_pair(self) -> Tuple[int, int]:
        p, q = 0, 0
        attempts = 0
        max_attempts = 100
        
        while True:
            if attempts > max_attempts:
                raise ValueError("Не удалось сгенерировать устойчивую пару простых чисел")
            
            attempts += 1
            p, q = await asyncio.gather(
                self._generate_prime(),
                self._generate_prime()
            )
            
            if (p != q and 
                CipherService.gcd(p, q) == 1 and 
                self._is_fermat_attack_resistant(p, q)):
                break
        
        return p, q
    
    async def generate_key_pair(self) -> RSAKeyPair:
        p, q = await self._generate_prime_pair()
        modulus = p * q
        phi = (p - 1) * (q - 1)
        
        standard_exponents = [65537, 257, 17]
        public_exponent = 65537
        private_exponent = None
        
        for e in standard_exponents:
            if CipherService.gcd(e, phi) == 1:
                gcd_val, x, y = CipherService.extended_gcd(e, phi)
                d = ((x % phi) + phi) % phi
                
                if self._is_wiener_attack_resistant(d, modulus):
                    public_exponent = e
                    private_exponent = d
                    break
        
        if private_exponent is None:
            while True:
                range_size = phi - 3 + 1
                random_bytes = secrets.token_bytes(128)
                
                e = 0
                for byte in random_bytes:
                    e = (e << 8) | byte
                
                e = 3 + (e % range_size)
                e |= 1
                
                if CipherService.gcd(e, phi) == 1:
                    gcd_val, x, y = CipherService.extended_gcd(e, phi)
                    d = ((x % phi) + phi) % phi
                    
                    if self._is_wiener_attack_resistant(d, modulus):
                        public_exponent = e
                        private_exponent = d
                        break
        
        return {
            'public_key': {'exponent': public_exponent, 'modulus': modulus},
            'private_key': {'exponent': private_exponent, 'modulus': modulus}
        }
    
    async def generate_weak_key_pair(self) -> RSAKeyPair:
        p, q = await self._generate_prime_pair()
        modulus = p * q
        phi = (p - 1) * (q - 1)
        
        max_d = AttacksService.sqrt(AttacksService.sqrt(modulus)) // 3
        
        while True:
            range_size = max_d - 3 + 1
            random_bytes = secrets.token_bytes(64)
            
            d = 0
            for byte in random_bytes:
                d = (d << 8) | byte
            
            d = 3 + (d % range_size)
            
            if CipherService.gcd(d, phi) == 1:
                break
        
        gcd_val, x, y = CipherService.extended_gcd(d, phi)
        e = ((x % phi) + phi) % phi
        
        return {
            'public_key': {'exponent': e, 'modulus': modulus},
            'private_key': {'exponent': d, 'modulus': modulus}
        }
    
    async def generate_weak_key_pair_for_fermat(self) -> RSAKeyPair:
        p = await self._generate_prime()
        q = 0
        diff = 1 << 20
        attempts = 0
        
        while True:
            attempts += 1
            if attempts > 100:
                p = await self._generate_prime()
                attempts = 0
            
            q = p + diff
            if q % 2 == 0:
                q += 1
            
            if self.test.is_primary(q, self.config.min_probability):
                break
        
        modulus = p * q
        phi = (p - 1) * (q - 1)
        
        public_exponent = 65537
        gcd_val, x, y = CipherService.extended_gcd(public_exponent, phi)
        private_exponent = ((x % phi) + phi) % phi
        
        return {
            'public_key': {'exponent': public_exponent, 'modulus': modulus},
            'private_key': {'exponent': private_exponent, 'modulus': modulus}
        }