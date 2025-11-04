from abc import ABC, abstractmethod
from math import log, ceil
import secrets

class PrimalityInterface(ABC):
    @abstractmethod
    def is_primary(self, n: int, probability: float) -> bool:
        pass

class BasePrimalityTest(PrimalityInterface):
    @property
    @abstractmethod
    def probabilistic_coef(self) -> float:
        pass
    
    @abstractmethod
    def test_once(self, n: int, a: int) -> bool:
        pass
    
    def calculate_rounds(self, probability: float) -> int:
        if probability < 0.5 or probability >= 1:
            raise ValueError("Вероятность должна быть в диапазоне [0.5, 1)")
        return ceil(-log(1.0 - probability) / log(self.probabilistic_coef))
    
    def get_random_base(self, n: int) -> int:
        if n <= 2:
            raise ValueError("n должно быть больше 2")
        
        min_val = 2
        max_val = n - 1
        range_size = max_val - min_val + 1
        
        num_bytes = (range_size.bit_length() + 7) // 8 + 8
        random_bytes = secrets.token_bytes(num_bytes)
        random_num = int.from_bytes(random_bytes, byteorder='big')
        
        return min_val + (random_num % range_size)
    
    def is_primary(self, n: int, probability: float = 0.99) -> bool:
        if n == 2:
            return True
        if n < 2 or n % 2 == 0:
            return False
        
        rounds = self.calculate_rounds(probability)
        
        for _ in range(rounds):
            base = self.get_random_base(n)
            if not self.test_once(n, base):
                return False
        
        return True