"""Galois Field GF(2^8) service implementation"""

from typing import Final
from src.galois.types import GFElement, Polynomial, IGaloisFieldService
from src.galois.constants import IRREDUCIBLE_POLYNOMIALS_8, AES_POLYNOMIAL
from src.utils.bit_utils import BitUtils


class GaloisFieldService:
    """Stateless service for GF(2^8) operations"""
    
    def __init__(self, modulus: Polynomial = AES_POLYNOMIAL) -> None:
        if not self.is_irreducible(modulus):
            raise ValueError(f"Polynomial 0x{modulus:02x} is reducible over GF(2^8)")
        self._modulus: Final[Polynomial] = modulus
    
    def add(self, a: GFElement, b: GFElement) -> GFElement:
        """Add two elements in GF(2^8) (XOR operation)"""
        return (a ^ b) & 0xFF
    
    def multiply(self, a: GFElement, b: GFElement) -> GFElement:
        """Multiply two elements in GF(2^8) modulo the configured modulus"""
        aa = a & 0xFF
        bb = b & 0xFF
        res = 0
        red = self._modulus & 0xFF
        
        while bb:
            if bb & 1:
                res ^= aa
            carry = aa & 0x80
            aa = (aa << 1) & 0xFF
            if carry:
                aa ^= red
            bb >>= 1
        
        return res & 0xFF
    
    def inverse(self, element: GFElement) -> GFElement:
        """Get the inverse of an element in GF(2^8) using extended Euclidean algorithm"""
        if element == 0:
            raise ValueError("Zero element has no inverse")
        
        if not self.is_irreducible(self._modulus):
            raise ValueError("Modulus is reducible over GF(2); inverse is undefined")
        
        r0 = self._modulus
        r1 = element & 0xFF
        t0 = 0
        t1 = 1
        
        while r1 != 0:
            division = BitUtils.divide_polynomials(r0, r1)
            q = division["quotient"]
            rem = division["remainder"]
            t = t0 ^ BitUtils.multiply_polynomials(t1, q)
            r0 = r1
            r1 = rem
            t0 = t1
            t1 = t
        
        if r0 != 1:
            raise ValueError("Element is not invertible for the given modulus")
        
        inv_division = BitUtils.divide_polynomials(t0, self._modulus)
        return inv_division["remainder"] & 0xFF
    
    def is_irreducible(self, polynomial: Polynomial) -> bool:
        """Check if a polynomial of degree 8 is irreducible over GF(2)"""
        degree = BitUtils.polynomial_degree(polynomial)
        if degree != 8:
            return False
        return polynomial in IRREDUCIBLE_POLYNOMIALS_8
    
    def get_all_irreducible_polynomials(self) -> list[Polynomial]:
        """Get all irreducible polynomials of degree 8 over GF(2)"""
        return list(IRREDUCIBLE_POLYNOMIALS_8)
    
    def factor_polynomial(self, polynomial: Polynomial) -> list[Polynomial]:
        """Factor a polynomial into irreducible factors"""
        if polynomial == 0:
            return [0]
        
        degree = BitUtils.polynomial_degree(polynomial)
        if degree < 0:
            return [0]
        if degree == 0:
            return [polynomial]
        
        factors: list[Polynomial] = []
        remaining = polynomial
        
        # Factor out x (polynomial 2)
        while (remaining & 1) == 0:
            factors.append(2)
            remaining >>= 1
        
        if remaining > 1:
            if self._is_polynomial_irreducible(remaining):
                factors.append(remaining)
            else:
                irreducible_factors = self._factor_using_irreducible_polynomials(remaining)
                factors.extend(irreducible_factors)
        
        return sorted(factors)
    
    def get_modulus(self) -> Polynomial:
        """Get the current modulus"""
        return self._modulus
    
    def _is_polynomial_irreducible(self, polynomial: Polynomial) -> bool:
        """Check if a polynomial is irreducible"""
        degree = BitUtils.polynomial_degree(polynomial)
        
        if degree <= 1:
            return True
        if degree == 8:
            return self.is_irreducible(polynomial)
        
        return self._check_irreducibility_by_trial_division(polynomial, degree)
    
    def _factor_using_irreducible_polynomials(self, polynomial: Polynomial) -> list[Polynomial]:
        """Factor polynomial using known irreducible polynomials"""
        factors: list[Polynomial] = []
        remaining = polynomial
        
        for irreducible in IRREDUCIBLE_POLYNOMIALS_8:
            irr_degree = BitUtils.polynomial_degree(irreducible)
            rem_degree = BitUtils.polynomial_degree(remaining)
            
            if irr_degree > rem_degree:
                break
            
            while True:
                division = BitUtils.divide_polynomials(remaining, irreducible)
                if division["remainder"] == 0:
                    factors.append(irreducible)
                    remaining = division["quotient"]
                    
                    if remaining == 1:
                        return factors
                    
                    if self._is_polynomial_irreducible(remaining):
                        factors.append(remaining)
                        return factors
                else:
                    break
        
        if remaining != 1:
            factors.append(remaining)
        
        return factors
    
    def _check_irreducibility_by_trial_division(
        self, 
        polynomial: Polynomial, 
        degree: int
    ) -> bool:
        """Check irreducibility by trial division"""
        if (polynomial & 1) == 0:
            return False
        if (polynomial & 2) == 0:
            return False
        
        for test_degree in range(1, degree // 2 + 1):
            start_poly = 1 << test_degree
            end_poly = 1 << (test_degree + 1)
            
            for test_poly in range(start_poly | 1, end_poly, 2):
                if BitUtils.polynomial_degree(test_poly) != test_degree:
                    continue
                
                division = BitUtils.divide_polynomials(polynomial, test_poly)
                if division["remainder"] == 0:
                    return False
        
        return True

