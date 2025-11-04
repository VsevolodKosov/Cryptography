from src.utils.primality.base import BasePrimalityTest
from src.utils.cipher_service import CipherService

class SolovayStrassenTest(BasePrimalityTest):
    @property
    def probabilistic_coef(self) -> float:
        return 2.0
    
    def test_once(self, n: int, a: int) -> bool:
        if CipherService.gcd(a, n) != 1:
            return False
        
        J = CipherService.Jacobi_symbol(a, n)
        exp = (n - 1) // 2
        power = CipherService.mod_pow(a, exp, n)
        
        if J == -1:
            return power == n - 1
        
        return power == J