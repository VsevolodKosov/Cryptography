from src.utils.primality.base import BasePrimalityTest
from src.utils.cipher_service import CipherService

class MillerRabinTest(BasePrimalityTest):
    
    @property
    def probabilistic_coef(self) -> float:
        return 4.0
    
    def test_once(self, n: int, a: int) -> bool:
        s = n - 1
        d = 0
        
        while s % 2 == 0:
            s //= 2
            d += 1
        
        x = CipherService.mod_pow(a, s, n)
        if x == 1:
            return True
        
        for i in range(d):
            if x == n - 1:
                return True
            x = CipherService.mod_pow(x, 2, n)
        
        return False