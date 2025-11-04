from typing import List, Dict

class AttacksService:
    
    @staticmethod
    def continued_fraction(x: Dict[str, int]) -> List[int]:
        result = []
        remainder = x.copy()
        
        while True:
            integer_part = remainder['numerator'] // remainder['denominator']
            result.append(integer_part)
            
            remainder['numerator'] = remainder['numerator'] - integer_part * remainder['denominator']
            
            if remainder['numerator'] == 0:
                break
            
            remainder['numerator'], remainder['denominator'] = remainder['denominator'], remainder['numerator']
        
        return result

    @staticmethod
    def calculate_convergents(cf: List[int]) -> List[Dict[str, int]]:
        result = []
        if not cf:
            return result

        p1, q1 = 0, 1
        p0, q0 = 1, 0

        for a in cf:
            p = a * p0 + p1
            q = a * q0 + q1
            
            result.append({'numerator': p, 'denominator': q})
            
            p1, q1 = p0, q0
            p0, q0 = p, q
        
        return result

    @staticmethod
    def sqrt(value: int) -> int:
        if value < 0:
            raise ValueError("Отрицательное значение")
        if value < 2:
            return value
        
        x = value
        y = (x + 1) // 2
        
        while y < x:
            x = y
            y = (x + value // x) // 2
        
        return x