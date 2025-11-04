from typing import List, Optional, TypedDict
from src.cipher.crypto_service import RSACryptoService
from attacks.attacks_service import AttacksService

class Rational(TypedDict):
    numerator: int
    denominator: int

class WienerAttackResult(TypedDict):
    success: bool
    private_exponent: Optional[int]
    phi: Optional[int]
    convergents: List[Rational]

class WienerAttack:
    
    @staticmethod
    def attack(rsa_service: RSACryptoService) -> WienerAttackResult:
        public_key = rsa_service.get_public_key()
        if not public_key:
            raise ValueError("Публичный ключ недоступен")
        
        e = public_key['exponent']
        n = public_key['modulus']
        
        e_over_n: Rational = {'numerator': e, 'denominator': n}
        
        continued_fraction = AttacksService.continued_fraction(e_over_n)
        convergents = AttacksService.calculate_convergents(continued_fraction)
        
        for convergent in convergents:
            success, phi = WienerAttack._test_convergent(n, e, convergent)
            if success:
                return {
                    'success': True,
                    'private_exponent': convergent['denominator'],
                    'phi': phi,
                    'convergents': convergents
                }
        
        return {
            'success': False,
            'private_exponent': None,
            'phi': None,
            'convergents': convergents
        }
    
    @staticmethod
    def _test_convergent(n: int, e: int, convergent: Rational) -> tuple[bool, Optional[int]]:
        k = convergent['numerator']
        d = convergent['denominator']
        
        if k == 0 or d == 0:
            return False, None
        
        if (e * d - 1) % k != 0:
            return False, None
        
        phi = (e * d - 1) // k
        
        b = n - phi + 1
        discriminant = b * b - 4 * n
        
        if discriminant < 0:
            return False, None
        
        root = AttacksService.sqrt(discriminant)
        if root * root != discriminant:
            return False, None
        
        p = (b + root) // 2
        q = (b - root) // 2
        
        if p > 1 and q > 1 and p * q == n:
            return True, phi
        
        return False, None