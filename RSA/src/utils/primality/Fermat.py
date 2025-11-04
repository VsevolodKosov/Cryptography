from src.utils.primality.base import BasePrimalityTest
from src.utils.cipher_service import CipherService

class FermatTest(BasePrimalityTest):
    @property
    def probabilistic_coef(self) -> float:
        return 2.0
    
    def test_once(self, n: int, a: int) -> bool:
        if CipherService.gcd(a, n) != 1:
            return False
        
        return CipherService.mod_pow(a, n - 1, n) == 1