import random
from src.utils.constants import BitOrder


def bytes_to_bits(data, bit_order=BitOrder.LSB):
    bits = []
    
    for byte in data:
        if bit_order == BitOrder.LSB:
            for i in range(8):
                bits.append((byte >> i) & 1)
        if bit_order == BitOrder.MSB:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
    
    return bits


def bits_to_bytes(bits, bit_order=BitOrder.LSB):
    result = []
    
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        
        if bit_order == BitOrder.LSB:
            byte_value = 0
            for j, bit in enumerate(chunk):
                byte_value |= (bit << j)
        if bit_order == BitOrder.MSB:
            byte_value = 0
            for j, bit in enumerate(chunk):
                byte_value |= (bit << (7 - j))
        
        result.append(byte_value & 0xFF)
    
    return bytes(result)


def xor_bytes(a, b):
    result = bytearray()
    for byte_a, byte_b in zip(a, b):
        result.append(byte_a ^ byte_b)
    
    return bytes(result)


def random_bytes(length):
    return bytes([random.randint(0, 255) for _ in range(length)])


def rotate_left(data, n):
    if not data:
        return data
    
    length = len(data)
    shift = n % length
    
    return data[shift:] + data[:shift]



def permutation(data, permutation, bit_order=BitOrder.LSB, start_at_zero=False):
    bits = bytes_to_bits(data, bit_order)
    
    result_bits = []
    for pos in permutation:
        if start_at_zero:
            bit_index = pos
        else:
            bit_index = pos - 1
        
        result_bits.append(bits[bit_index])

    return bits_to_bytes(result_bits, bit_order)


