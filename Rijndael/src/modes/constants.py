"""Constants for cipher modes and padding"""

from enum import Enum


class CipherMode(Enum):
    """Cipher modes of operation"""
    ECB = 'ECB'
    CBC = 'CBC'
    PCBC = 'PCBC'
    CFB = 'CFB'
    OFB = 'OFB'
    CTR = 'CTR'
    RandomDelta = 'RandomDelta'


class PaddingMode(Enum):
    """Padding modes"""
    Zeros = 'Zeros'
    ANSI_X923 = 'ANSI_X923'
    PKCS7 = 'PKCS7'
    ISO_10126 = 'ISO_10126'
    NONE = 'NONE'

