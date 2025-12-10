"""Type definitions for Galois Field operations"""

from typing import Protocol

# Type aliases
GFElement = int
Polynomial = int


class IGaloisFieldService(Protocol):
    """Protocol for Galois Field service interface"""
    
    def add(self, a: GFElement, b: GFElement) -> GFElement:
        """Add two elements in GF(2^8)"""
        ...
    
    def multiply(self, a: GFElement, b: GFElement) -> GFElement:
        """Multiply two elements in GF(2^8)"""
        ...
    
    def inverse(self, element: GFElement) -> GFElement:
        """Get the inverse of an element in GF(2^8)"""
        ...
    
    def is_irreducible(self, polynomial: Polynomial) -> bool:
        """Check if a polynomial of degree 8 is irreducible over GF(2)"""
        ...
    
    def get_all_irreducible_polynomials(self) -> list[Polynomial]:
        """Get all irreducible polynomials of degree 8 over GF(2)"""
        ...
    
    def factor_polynomial(self, polynomial: Polynomial) -> list[Polynomial]:
        """Factor a polynomial into irreducible factors"""
        ...

