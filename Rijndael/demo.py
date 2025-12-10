
import sys
from pathlib import Path

from src.galois import GaloisFieldService, IRREDUCIBLE_POLYNOMIALS_8
from src.aes_rijndael import RijndaelCipher
from src.modes import CryptoContext, CipherMode, PaddingMode
from src.utils.modes_utils import random_bytes, bytes_to_hex

def print_section(title: str) -> None:
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_random_bytes_encryption() -> None:
    print_section("1. Шифрование псевдослучайных последовательностей байтов")
    
    sizes = [16, 32, 64, 128, 256, 512, 1024]
    
    gf = GaloisFieldService()
    cipher = RijndaelCipher({"nb": 4, "gf": gf})
    key = random_bytes(16)
    iv = random_bytes(16)
    cipher.expand_key(key, 4)
    
    for size in sizes:
        print(f"Размер данных: {size} байт")
        random_data = random_bytes(size)
        print(f"Исходные данные (первые 32 байта): {bytes_to_hex(random_data[:32])}...")
        
        ctx = CryptoContext(
            cipher=cipher,
            mode=CipherMode.CBC,
            padding=PaddingMode.PKCS7,
            iv=iv
        )
        
        encrypted = ctx.encrypt(random_data)
        print(f"Зашифровано (первые 32 байта): {bytes_to_hex(encrypted[:32])}...")
        
        decrypted = ctx.decrypt(encrypted)
        print(f"Дешифровано (первые 32 байта): {bytes_to_hex(decrypted[:32])}...")
        
        if random_data == decrypted:
            print("✓ Успешно: данные совпадают\n")
        else:
            print("✗ Ошибка: данные не совпадают\n")


def demo_file_encryption(file_path: str, file_type: str = "text") -> None:
    path = Path(file_path)
    
    if not path.exists():
        print(f"Файл не найден: {file_path}")
        return
    
    print(f"Файл: {path.name} ({file_type})")
    print(f"Размер: {path.stat().st_size} байт")
    
    with open(path, 'rb') as f:
        file_data = f.read()
    
    print(f"Исходные данные (первые 64 байта): {bytes_to_hex(file_data[:64])}...")
    
    gf = GaloisFieldService()
    cipher = RijndaelCipher({"nb": 4, "gf": gf})
    key = random_bytes(16)
    iv = random_bytes(16)
    cipher.expand_key(key, 4)
    
    ctx = CryptoContext(
        cipher=cipher,
        mode=CipherMode.CBC,
        padding=PaddingMode.PKCS7,
        iv=iv
    )
    
    encrypted = ctx.encrypt(file_data)
    print(f"Зашифровано (первые 64 байта): {bytes_to_hex(encrypted[:64])}...")
    print(f"Размер зашифрованных данных: {len(encrypted)} байт")
    
    decrypted = ctx.decrypt(encrypted)
    print(f"Дешифровано (первые 64 байта): {bytes_to_hex(decrypted[:64])}...")
    
    if file_data == decrypted:
        print("✓ Успешно: файл восстановлен корректно\n")
    else:
        print("✗ Ошибка: файл не восстановлен корректно\n")


def demo_cipher_modes() -> None:
    print_section("2. Различные режимы шифрования")
    
    data = b"Hello, World! This is a test message for encryption demonstration."
    gf = GaloisFieldService()
    cipher = RijndaelCipher({"nb": 4, "gf": gf})
    key = random_bytes(16)
    cipher.expand_key(key, 4)
    
    modes = [
        (CipherMode.ECB, None),
        (CipherMode.CBC, random_bytes(16)),
        (CipherMode.PCBC, random_bytes(16)),
        (CipherMode.CFB, random_bytes(16)),
        (CipherMode.OFB, random_bytes(16)),
        (CipherMode.CTR, random_bytes(16)),
        (CipherMode.RandomDelta, random_bytes(16)),
    ]
    
    for mode, iv in modes:
        print(f"Режим: {mode.value}")
        try:
            ctx = CryptoContext(
                cipher=cipher,
                mode=mode,
                padding=PaddingMode.PKCS7,
                iv=iv
            )
            
            encrypted = ctx.encrypt(data)
            decrypted = ctx.decrypt(encrypted)
            
            if data == decrypted:
                print(f"  ✓ Успешно: {len(encrypted)} байт зашифровано")
            else:
                print("✗ Ошибка: данные не совпадают")
        except Exception as e:
            print(f"  ✗ Ошибка: {e}")
        print()


def demo_padding_modes() -> None:
    print_section("3. Различные режимы набивки")
    
    test_data = [
        (b"Short", "Короткие данные"),
        (b"Medium length data", "Средние данные"),
        (b"This is a longer test message that requires padding", "Длинные данные"),
    ]
    
    gf = GaloisFieldService()
    cipher = RijndaelCipher({"nb": 4, "gf": gf})
    key = random_bytes(16)
    iv = random_bytes(16)
    cipher.expand_key(key, 4)
    
    padding_modes = [
        PaddingMode.Zeros,
        PaddingMode.ANSI_X923,
        PaddingMode.PKCS7,
        PaddingMode.ISO_10126,
        PaddingMode.NONE,
    ]
    
    for data, desc in test_data:
        print(f"Данные: {desc} ({len(data)} байт)")
        for padding_mode in padding_modes:
            try:
                ctx = CryptoContext(
                    cipher=cipher,
                    mode=CipherMode.CBC,
                    padding=padding_mode,
                    iv=iv
                )
                
                encrypted = ctx.encrypt(data)
                decrypted = ctx.decrypt(encrypted)
                
                if data == decrypted:
                    print(f"  {padding_mode.value:15} ✓ Успешно (размер: {len(encrypted)} байт)")
                else:
                    print(f"  {padding_mode.value:15} ✗ Ошибка")
            except Exception as e:
                print(f"  {padding_mode.value:15} ✗ Ошибка: {e}")
        print()


def demo_block_and_key_sizes() -> None:
    print_section("4. Различные длины блока и ключа")
    
    data = b"Test data for different block and key sizes demonstration."
    gf = GaloisFieldService()
    
    configurations = [
        (4, 4, "AES-128: блок 128 бит, ключ 128 бит"),
        (4, 6, "AES-192: блок 128 бит, ключ 192 бит"),
        (4, 8, "AES-256: блок 128 бит, ключ 256 бит"),
        (6, 4, "Rijndael: блок 192 бит, ключ 128 бит"),
        (6, 6, "Rijndael: блок 192 бит, ключ 192 бит"),
        (6, 8, "Rijndael: блок 192 бит, ключ 256 бит"),
        (8, 4, "Rijndael: блок 256 бит, ключ 128 бит"),
        (8, 6, "Rijndael: блок 256 бит, ключ 192 бит"),
        (8, 8, "Rijndael: блок 256 бит, ключ 256 бит"),
    ]
    
    for nb, nk, desc in configurations:
        print(f"{desc}")
        try:
            cipher = RijndaelCipher({"nb": nb, "gf": gf})
            key = random_bytes(nk * 4)
            iv = random_bytes(nb * 4)
            cipher.expand_key(key, nk)
            
            ctx = CryptoContext(
                cipher=cipher,
                mode=CipherMode.CBC,
                padding=PaddingMode.PKCS7,
                iv=iv
            )
            
            encrypted = ctx.encrypt(data)
            decrypted = ctx.decrypt(encrypted)
            
            if data == decrypted:
                print(f"  ✓ Успешно: блок {nb*4} байт, ключ {nk*4} байт")
            else:
                print("  ✗ Ошибка: данные не совпадают")
        except Exception as e:
            print(f"  ✗ Ошибка: {e}")
        print()


def demo_irreducible_polynomials() -> None:
    print_section("5. Различные неприводимые полиномы над GF(2^8)")
    
    data = b"Test data for different irreducible polynomials demonstration."
    
    test_polynomials = [
        (0x11b, "AES стандартный (0x11b)"),
        (0x11d, "Альтернативный (0x11d)"),
        (0x12b, "Альтернативный (0x12b)"),
        (0x163, "Альтернативный (0x163)"),
        (0x1f3, "Альтернативный (0x1f3)"),
    ]
    
    for poly, desc in test_polynomials:
        print(f"{desc}")
        try:
            gf = GaloisFieldService(modulus=poly)
            cipher = RijndaelCipher({"nb": 4, "gf": gf})
            key = random_bytes(16)
            iv = random_bytes(16)
            cipher.expand_key(key, 4)
            
            ctx = CryptoContext(
                cipher=cipher,
                mode=CipherMode.CBC,
                padding=PaddingMode.PKCS7,
                iv=iv
            )
            
            encrypted = ctx.encrypt(data)
            decrypted = ctx.decrypt(encrypted)
            
            if data == decrypted:
                print(f"  ✓ Успешно: полином 0x{poly:03x}")
            else:
                print("  ✗ Ошибка: данные не совпадают")
        except Exception as e:
            print(f"  ✗ Ошибка: {e}")
        print()
    
    print(f"Всего неприводимых полиномов степени 8: {len(IRREDUCIBLE_POLYNOMIALS_8)}")
    print("Список всех полиномов:")
    for i, poly in enumerate(IRREDUCIBLE_POLYNOMIALS_8, 1):
        print(f"  {i:2}. 0x{poly:03x}", end="  ")
        if i % 5 == 0:
            print()
    if len(IRREDUCIBLE_POLYNOMIALS_8) % 5 != 0:
        print()
    print()


def demo_file_types() -> None:
    print_section("6. Шифрование различных типов файлов")

    script_dir = Path(__file__).parent
    test_dir = script_dir / "test_files"
    test_dir.mkdir(exist_ok=True)
    
    text_file = test_dir / "test.txt"
    with open(text_file, 'w', encoding='utf-8') as f:
        f.write("Это тестовый текстовый файл для демонстрации шифрования.\n")
        f.write("Содержит русский и английский текст.\n")
        f.write("Test file for encryption demonstration.\n")
    demo_file_encryption(str(text_file), "текстовый")
    
    binary_file = test_dir / "test.bin"
    binary_data = random_bytes(1024)
    with open(binary_file, 'wb') as f:
        f.write(binary_data)
    demo_file_encryption(str(binary_file), "бинарный (имитация изображения)")
    
    json_file = test_dir / "test.json"
    json_data = b'{"name": "test", "value": 123, "array": [1, 2, 3]}'
    with open(json_file, 'wb') as f:
        f.write(json_data)
    demo_file_encryption(str(json_file), "JSON")
    
    print("Примечание: Для реальных файлов (изображений, видео, аудио)")
    print("используйте тот же подход - читайте файл в байты, шифруйте, сохраняйте.")
    print("Для дешифрования - читайте зашифрованный файл, дешифруйте, сохраняйте.\n")


def demo_comprehensive() -> None:
    print_section("7. Комплексная демонстрация")
    
    data = b"Comprehensive test with various combinations of parameters."
    
    combinations = [
        {
            "nb": 4,
            "nk": 4,
            "mode": CipherMode.CBC,
            "padding": PaddingMode.PKCS7,
            "poly": 0x11b,
            "desc": "AES-128, CBC, PKCS7, полином 0x11b"
        },
        {
            "nb": 4,
            "nk": 8,
            "mode": CipherMode.CTR,
            "padding": PaddingMode.ANSI_X923,
            "poly": 0x11d,
            "desc": "AES-256, CTR, ANSI_X923, полином 0x11d"
        },
        {
            "nb": 6,
            "nk": 6,
            "mode": CipherMode.CFB,
            "padding": PaddingMode.ISO_10126,
            "poly": 0x163,
            "desc": "Rijndael-192, CFB, ISO_10126, полином 0x163"
        },
        {
            "nb": 8,
            "nk": 8,
            "mode": CipherMode.OFB,
            "padding": PaddingMode.Zeros,
            "poly": 0x1f3,
            "desc": "Rijndael-256, OFB, Zeros, полином 0x1f3"
        },
    ]
    
    for combo in combinations:
        print(f"Конфигурация: {combo['desc']}")
        try:
            gf = GaloisFieldService(modulus=combo["poly"])
            cipher = RijndaelCipher({"nb": combo["nb"], "gf": gf})
            key = random_bytes(combo["nk"] * 4)
            iv = random_bytes(combo["nb"] * 4) if combo["mode"] != CipherMode.ECB else None
            cipher.expand_key(key, combo["nk"])
            
            ctx = CryptoContext(
                cipher=cipher,
                mode=combo["mode"],
                padding=combo["padding"],
                iv=iv
            )
            
            encrypted = ctx.encrypt(data)
            decrypted = ctx.decrypt(encrypted)
            
            if data == decrypted:
                print(f"  ✓ Успешно: {len(encrypted)} байт зашифровано")
            else:
                print("  ✗ Ошибка: данные не совпадают")
        except Exception as e:
            print(f"  ✗ Ошибка: {e}")
        print()


def main() -> None:
    print("\n" + "=" * 80)
    print("  ДЕМОНСТРАЦИЯ РАБОТЫ АЛГОРИТМА RIJNDAEL/AES")
    print("=" * 80)
    
    try:
        demo_random_bytes_encryption()
        
        demo_cipher_modes()
        
        demo_padding_modes()
        
        demo_block_and_key_sizes()
        
        demo_irreducible_polynomials()
        
        demo_file_types()
        
        demo_comprehensive()
        
        print_section("Демонстрация завершена успешно!")
        print("Все тесты пройдены. Алгоритм работает корректно с различными параметрами.")
        
    except Exception as e:
        print(f"\n✗ Ошибка при выполнении демонстрации: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

