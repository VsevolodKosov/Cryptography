"""Bit manipulation utilities for polynomial operations"""


class BitUtils:
    """Static utility methods for polynomial bit operations"""
    
    @staticmethod
    def polynomial_degree(polynomial: int) -> int:
        """Calculate the degree of a polynomial"""
        if polynomial == 0:
            return -1
        degree = 0
        temp = polynomial
        while temp > 0:
            degree += 1
            temp >>= 1
        return degree - 1
    
    @staticmethod
    def divide_polynomials(dividend: int, divisor: int) -> dict[str, int]:
        """Divide two polynomials, returning quotient and remainder"""
        if divisor == 0:
            raise ValueError("Division by zero")
        
        quotient = 0
        remainder = dividend
        divisor_degree = BitUtils.polynomial_degree(divisor)
        
        while BitUtils.polynomial_degree(remainder) >= divisor_degree:
            shift = BitUtils.polynomial_degree(remainder) - divisor_degree
            quotient ^= (1 << shift)
            remainder ^= (divisor << shift)
        
        return {"quotient": quotient, "remainder": remainder}
    
    @staticmethod
    def polynomial_gcd(a: int, b: int) -> int:
        """Calculate GCD of two polynomials"""
        while b != 0:
            temp = b
            division = BitUtils.divide_polynomials(a, b)
            b = division["remainder"]
            a = temp
        return a
    
    @staticmethod
    def multiply_polynomials(a: int, b: int) -> int:
        """Multiply two polynomials"""
        result = 0
        for i in range(32):
            if b & (1 << i):
                result ^= (a << i)
        return result

