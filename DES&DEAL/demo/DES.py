import asyncio
import time
import shutil
from pathlib import Path

from src.CryptoContext import CryptoContext
from src.DES.DESCipher import DESCipher
from src.DES.DESKeyExpansion import DESKeyExpansion
from src.utils.constants import CipherMode, PaddingMode


class DESDemo:
    def __init__(self):
        self.key = bytes([0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1])
        self.iv = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        self.results_dir = Path('demo_results')
        self.results_dir.mkdir(exist_ok=True)
    
    def cleanup_directories(self):
        """Очищает папки results и test_files"""
        test_files_dir = Path('test_files')
        if test_files_dir.exists():
            shutil.rmtree(test_files_dir)
        
        if self.results_dir.exists():
            shutil.rmtree(self.results_dir)
        
    def generate_test_files(self):
        """Генерирует тестовые файлы различных типов"""
        test_dir = Path('test_files')
        test_dir.mkdir(exist_ok=True)
        
        # Текстовый файл
        with open(test_dir / 'text.txt', 'w', encoding='utf-8') as f:
            f.write('Hello, DES! Тестирование шифрования DES алгоритма с различными режимами.\n' * 10)
        
        # Псевдослучайная последовательность - малые размеры
        small_random = bytes([i % 256 for i in range(128)])
        with open(test_dir / 'random_small.bin', 'wb') as f:
            f.write(small_random)
        
        # Псевдослучайная последовательность - средние размеры
        medium_random = bytes([i % 256 for i in range(1024)])
        with open(test_dir / 'random_medium.bin', 'wb') as f:
            f.write(medium_random)
        
        # Псевдослучайная последовательность - большие размеры
        large_random = bytes([i % 256 for i in range(8192)])
        with open(test_dir / 'random_large.bin', 'wb') as f:
            f.write(large_random)
        
        # Простое изображение BMP
        bmp_data = self.create_bmp_image(64, 64)
        with open(test_dir / 'test_image.bmp', 'wb') as f:
            f.write(bmp_data)
        
        return test_dir
    
    def create_bmp_image(self, width, height):
        """Создает простое BMP изображение"""
        header_size = 54
        data_size = width * height * 3
        file_size = header_size + data_size
        
        bmp = bytearray(file_size)
        
        bmp[0:2] = b'BM'
        bmp[2:6] = file_size.to_bytes(4, 'little')
        bmp[10:14] = header_size.to_bytes(4, 'little')
        bmp[14:18] = (40).to_bytes(4, 'little')
        bmp[18:22] = width.to_bytes(4, 'little')
        bmp[22:26] = height.to_bytes(4, 'little')
        bmp[26:28] = (1).to_bytes(2, 'little')
        bmp[28:30] = (24).to_bytes(2, 'little')
        bmp[34:38] = data_size.to_bytes(4, 'little')
        
        offset = header_size
        for y in range(height):
            for x in range(width):
                bmp[offset] = int(x * 255 / width)
                bmp[offset + 1] = int(y * 255 / height)
                bmp[offset + 2] = 128
                offset += 3
        
        return bytes(bmp)
    
    async def test_mode(self, data: bytes, mode: CipherMode, name: str):
        """Тестирует шифрование в указанном режиме"""
        cipher = DESCipher()
        key_expansion = DESKeyExpansion()
        round_keys = key_expansion.generate_round_keys(self.key)
        cipher.set_round_keys(round_keys)
        
        iv = self.iv if mode != CipherMode.ECB else None
        context = CryptoContext(cipher, mode, PaddingMode.PKCS7, iv)
        
        # Синхронное шифрование
        start = time.time()
        encrypted = context.encrypt(data)
        encrypt_time = time.time() - start
        
        # Синхронное дешифрование
        start = time.time()
        decrypted = context.decrypt(encrypted)
        decrypt_time = time.time() - start
        
        # Асинхронное шифрование
        start = time.time()
        encrypted_async = await context.encrypt_async(data)
        encrypt_async_time = time.time() - start
        
        # Асинхронное дешифрование
        start = time.time()
        decrypted_async = await context.decrypt_async(encrypted_async)
        decrypt_async_time = time.time() - start
        
        success = data == decrypted and data == decrypted_async
        
        return {
            'name': name,
            'mode': mode.name,
            'data_size': len(data),
            'success': success,
            'sync_encrypt': encrypt_time * 1000,
            'sync_decrypt': decrypt_time * 1000,
            'async_encrypt': encrypt_async_time * 1000,
            'async_decrypt': decrypt_async_time * 1000,
            'encrypted_size': len(encrypted),
            'encrypted': encrypted,
            'decrypted': decrypted
        }
    
    async def run_demo(self):
        """Запускает демонстрацию"""
        print("=" * 80)
        print("ДЕМОНСТРАЦИЯ DES АЛГОРИТМА")
        print("=" * 80)
        print()
        
        test_dir = self.generate_test_files()
        
        test_files = [
            ('text.txt', 'Текстовый файл'),
            ('random_small.bin', 'Псевдослучайная последовательность 128 байт'),
            ('random_medium.bin', 'Псевдослучайная последовательность 1024 байт'),
            ('random_large.bin', 'Псевдослучайная последовательность 8192 байт'),
            ('test_image.bmp', 'Изображение BMP')
        ]
        
        modes = [
            CipherMode.ECB,
            CipherMode.CBC,
            CipherMode.CFB,
            CipherMode.OFB,
            CipherMode.CTR
        ]
        
        results = []
        
        for filename, description in test_files:
            file_path = test_dir / filename
            
            if not file_path.exists():
                print(f"Файл {filename} не найден, пропускаем...")
                continue
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            print(f"\n{description} ({filename})")
            print(f"   Размер: {len(data)} байт")
            print("-" * 80)
            
            file_results = []
            
            for mode in modes:
                result = await self.test_mode(data, mode, filename)
                file_results.append(result)
                file_size_kb = max(len(data) / 1024, 0.001)
                
                print(f"\n  Режим: {mode.name}")
                print(f"  Корректность: {'OK' if result['success'] else 'FAIL'}")
                print(f"  Sync encrypt: {result['sync_encrypt']:.2f} мс ({result['sync_encrypt']/file_size_kb:.2f} мс/KB)")
                print(f"  Sync decrypt: {result['sync_decrypt']:.2f} мс ({result['sync_decrypt']/file_size_kb:.2f} мс/KB)")
                print(f"  Async encrypt: {result['async_encrypt']:.2f} мс ({result['async_encrypt']/file_size_kb:.2f} мс/KB)")
                print(f"  Async decrypt: {result['async_decrypt']:.2f} мс ({result['async_decrypt']/file_size_kb:.2f} мс/KB)")
                print(f"  Зашифрованный размер: {result['encrypted_size']} байт (увеличение: {result['encrypted_size'] - len(data)} байт)")
                
                if result['success']:
                    encrypted_path = self.results_dir / f'DES_{filename}_{mode.name}.enc'
                    with open(encrypted_path, 'wb') as f:
                        f.write(result['encrypted'])
            
            results.extend(file_results)
        
        # Итоговая статистика
        print("\n" + "=" * 80)
        print("ИТОГОВАЯ СТАТИСТИКА")
        print("=" * 80)
        
        total_tests = len(results)
        successful_tests = sum(1 for r in results if r['success'])
        
        print(f"\nВсего тестов: {total_tests}")
        print(f"Успешных: {successful_tests}")
        print(f"Неудачных: {total_tests - successful_tests}")
        
        avg_sync_encrypt = sum(r['sync_encrypt'] for r in results) / len(results)
        avg_sync_decrypt = sum(r['sync_decrypt'] for r in results) / len(results)
        avg_async_encrypt = sum(r['async_encrypt'] for r in results) / len(results)
        avg_async_decrypt = sum(r['async_decrypt'] for r in results) / len(results)
        
        print(f"\nСреднее время:")
        print(f"  Sync encrypt: {avg_sync_encrypt:.2f} мс")
        print(f"  Sync decrypt: {avg_sync_decrypt:.2f} мс")
        print(f"  Async encrypt: {avg_async_encrypt:.2f} мс")
        print(f"  Async decrypt: {avg_async_decrypt:.2f} мс")
        
        print(f"\nУскорение async по сравнению с sync:")
        print(f"  Encrypt: {avg_sync_encrypt / avg_async_encrypt:.2f}x")
        print(f"  Decrypt: {avg_sync_decrypt / avg_async_decrypt:.2f}x")
        
        print("\nДемонстрация завершена!")
        print(f"Результаты сохранены в: {self.results_dir}")
        
        print("\nОчистка временных файлов...")
        self.cleanup_directories()


if __name__ == "__main__":
    demo = DESDemo()
    asyncio.run(demo.run_demo())

