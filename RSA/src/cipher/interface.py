from enum import Enum
from typing import Protocol

class PrimalityTestType(Enum):
    FERMAT = "fermat"
    SOLOVAY_STRASSEN = "solovay_strassen" 
    MILLER_RABIN = "miller_rabin"

class RSAPublicKey(Protocol):
    exponent: int
    modulus: int

class RSAPrivateKey(Protocol):
    exponent: int
    modulus: int

class RSAKeyPair(Protocol):
    public_key: RSAPublicKey
    private_key: RSAPrivateKey

class RSAKeyGeneratorConfig(Protocol):
    test_type: PrimalityTestType
    min_probability: float
    bit_length: int