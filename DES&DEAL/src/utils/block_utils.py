from src.utils.constants import PaddingMode
from src.utils.bit_utils import random_bytes


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    if len(data) % block_size != 0:
        raise ValueError(
            "Не удалось разбить сообщение на блоки фиксированного размера. "
            "Количество байт в сообщении должно быть кратным размеру блока"
        )
    
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def join_blocks(blocks: list[bytes]) -> bytes:
    return b''.join(blocks)


def padding(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("Размер блока должен быть в диапозоне [0, 255]")

    pad_len = block_size - (len(data) % block_size)
    
    if mode == PaddingMode.ZEROS:
        return data + bytes(pad_len)
    elif mode == PaddingMode.ANSI_X923:
        return data + bytes(pad_len - 1) + bytes([pad_len])
    elif mode == PaddingMode.PKCS7:
        return data + bytes([pad_len] * pad_len)
    elif mode == PaddingMode.ISO_10126:
        return data + random_bytes(pad_len - 1) + bytes([pad_len])
    else:
        return data


def unpadding(data: bytes, mode: PaddingMode) -> bytes:
    if len(data) == 0:
        return data

    if mode == PaddingMode.ZEROS:
        end_index = len(data)
        while end_index > 0 and data[end_index - 1] == 0:
            end_index -= 1
        return data[:end_index]
    
    elif mode in (PaddingMode.ANSI_X923, PaddingMode.PKCS7, PaddingMode.ISO_10126):
        pad_len = data[-1]
        if pad_len == 0 or pad_len > len(data):
            raise ValueError("Некорректное значение размера набивки." 
                "Ожидается, что набивка присутствует и ее размер не превышает размер сообщения."
            )
        
        if mode == PaddingMode.PKCS7:
            for i in range(len(data) - pad_len, len(data)):
                if data[i] != pad_len:
                    raise ValueError("Ошибка режима набивки." 
                        "Для PKCS7 ожидается, что каждый байт набивки равен размеру набивки."
                    )
                
        elif mode == PaddingMode.ANSI_X923:
            for i in range(len(data) - pad_len, len(data) - 1):
                if data[i] != 0:
                    raise ValueError("Ошибка режима набивки. " 
                        "Для ANSI X.923 ожидается, что каждый байт набивки равен нулю."
                    )
        
        return data[:-pad_len]
    
    else:
        return data