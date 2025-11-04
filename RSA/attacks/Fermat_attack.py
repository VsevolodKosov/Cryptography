from typing import List, Optional, TypedDict
from src.cipher.interface import RSAPublicKey
from attacks.attacks_service import AttacksService

class FermatAttackResult(TypedDict):
    success: bool
    factors: Optional[List[int]]
    attempts: int

class FermatAttack:
    
    @staticmethod
    def attack(public_key: RSAPublicKey, max_attempts: int = 10000) -> FermatAttackResult:
        n = public_key['modulus']
        attempts = 0
        
        if n % 2 == 0:
            return {
                'success': True,
                'factors': [2, n // 2],
                'attempts': 1
            }
        
        a = AttacksService.sqrt(n)
        if a * a == n:
            return {
                'success': True,
                'factors': [a, a],
                'attempts': 1
            }
        
        a += 1
        
        while attempts < max_attempts:
            attempts += 1
            
            b_squared = a * a - n
            if b_squared < 0:
                a += 1
                continue
            
            b = AttacksService.sqrt(b_squared)
            
            if b * b == b_squared:
                p = a - b
                q = a + b
                
                if p > 1 and q > 1 and p * q == n:
                    return {
                        'success': True,
                        'factors': [p, q],
                        'attempts': attempts
                    }
            
            a += 1
        
        return {
            'success': False,
            'factors': None,
            'attempts': attempts
        }
    
    @staticmethod
    def is_vulnerable(public_key: RSAPublicKey) -> bool:
        test_result = FermatAttack.attack(public_key, 1000)
        return test_result['success']