from typing import List

class CipherService:

    @staticmethod 
    def gcd(a: int, b: int) -> int:
        while b != 0:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> List[int]:
        sign_a = 1 if a >= 0 else -1
        sign_b = 1 if b >= 0 else -1
        a, b = abs(a), abs(b)

        if b == 0:
            return [a, sign_b, 0]
        
        x0, x1 = 1, 0
        y0, y1 = 0, 1

        while b != 0:
            quotient = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - quotient * x1
            y0, y1 = y1, y0 - quotient * y1

        x0 *= sign_a
        y0 *= sign_b

        return [a, x0, y0]
    
    @staticmethod
    def mod_pow(base: int, exp: int, mod: int) -> int:
        if exp < 0:
            raise ValueError("Показатель должен быть положительным")
        
        base = ((base % mod) + mod) % mod
        result = 1
        
        while exp > 0:
            if exp & 1:
                result = (result * base) % mod
            base = (base * base) % mod
            exp >>= 1
        
        return result
    
    @staticmethod
    def Jacobi_symbol(a: int, n: int) -> int:
        if n < 2:
            raise ValueError("N должен быть не меньше двух")
        if n % 2 == 0:
            raise ValueError("N должен быть четным")
        
        # Проверка взаимной простоты
        if CipherService.gcd(a, n) != 1:
            return 0
        
        result = 1
        a_val = a
        n_val = n
        
        # Обработка отрицательного a
        if a_val < 0:
            a_val = -a_val
            if n_val % 4 == 3:
                result *= -1
        
        while a_val != 0:
            # Вынесение степеней двойки из a_val
            t = 0
            while a_val % 2 == 0:
                t += 1
                a_val //= 2
            
            # Обработка вынесенных двоек
            if t % 2 == 1:
                mod8 = n_val % 8
                if mod8 == 3 or mod8 == 5:
                    result *= -1
            
            # Квадратичный закон взаимности
            if a_val % 4 == 3 and n_val % 4 == 3:
                result *= -1
            
            # "Переворот" аргументов
            a_val, n_val = n_val % a_val, a_val
        
        return result if n_val == 1 else 0
    
    @staticmethod 
    def Legendre_symbol(a: int, p: int, primality_tester) -> int:
        # Проверка что p - простое число
        if not primality_tester.is_primary(p, 0.99):
            raise ValueError("p должно быть простым числом")
        
        return CipherService.Jacobi_symbol(a, p)