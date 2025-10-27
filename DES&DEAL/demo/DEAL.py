import asyncio
import time
import shutil
from pathlib import Path

from src.CryptoContext import CryptoContext
from src.DEAL.DEALCipher import DEALCipher
from src.utils.constants import CipherMode, PaddingMode


class DEALDemo:
    def __init__(self):
        self.keys = {
            'DEAL-128': bytes([1] * 16),
            'DEAL-192': bytes([2] * 24), 
            'DEAL-256': bytes([3] * 32)
        }
        self.iv = bytes([4] * 16)
        self.results_dir = Path('deal_demo_results')
        self.results_dir.mkdir(exist_ok=True)
    
    def cleanup_directories(self):
        """Очищает папки results и test_files"""
        for dir_path in [Path('test_files'), self.results_dir]:
            if dir_path.exists():
                shutil.rmtree(dir_path)
        
    def generate_test_files(self):
        """Генерирует тестовые файлы"""
        test_dir = Path('test_files')
        test_dir.mkdir(exist_ok=True)
        
        # Текстовый файл
        with open(test_dir / 'text.txt', 'w', encoding='utf-8') as f:
            f.write('Hello, DEAL! Тестирование шифрования.\n' * 10)
        
        # Псевдослучайные данные разных размеров
        sizes = [256, 1024, 4096]  # Уменьшены размеры
        for size in sizes:
            random_data = bytes([i % 256 for i in range(size)])
            with open(test_dir / f'random_{size}.bin', 'wb') as f:
                f.write(random_data)
        
        # Уменьшенное BMP изображение 32x32
        bmp_data = self.create_bmp_image(32, 32)  # Было 128x128
        with open(test_dir / 'test_image.bmp', 'wb') as f:
            f.write(bmp_data)
        
        # JSON файл
        json_data = '{"test": "data", "value": 123}'
        with open(test_dir / 'data.json', 'w') as f:
            f.write(json_data)
        
        return test_dir
    
    def create_bmp_image(self, width, height):
        """Создает маленькое BMP изображение 32x32"""
        header_size = 54
        data_size = width * height * 3
        file_size = header_size + data_size
        
        bmp = bytearray(file_size)
        
        # BMP заголовок
        bmp[0:2] = b'BM'
        bmp[2:6] = file_size.to_bytes(4, 'little')
        bmp[10:14] = header_size.to_bytes(4, 'little')
        bmp[14:18] = (40).to_bytes(4, 'little')  # DIB header size
        bmp[18:22] = width.to_bytes(4, 'little')
        bmp[22:26] = height.to_bytes(4, 'little')
        bmp[26:28] = (1).to_bytes(2, 'little')   # planes
        bmp[28:30] = (24).to_bytes(2, 'little')  # bits per pixel
        bmp[34:38] = data_size.to_bytes(4, 'little')
        
        # Пиксельные данные (простой градиент)
        offset = header_size
        for y in range(height):
            for x in range(width):
                bmp[offset] = int(x * 255 / width)      # Blue
                bmp[offset + 1] = int(y * 255 / height) # Green  
                bmp[offset + 2] = 128                   # Red
                offset += 3
        
        return bytes(bmp)
    
    async def test_mode(self, data: bytes, mode: CipherMode, key_name: str, key_bytes: bytes):
        """Тестирует шифрование в указанном режиме"""
        cipher = DEALCipher(key_bytes)
        iv = self.iv if mode != CipherMode.ECB else None
        context = CryptoContext(cipher, mode, PaddingMode.PKCS7, iv)
        
        # Синхронное шифрование/дешифрование
        start = time.time()
        encrypted = context.encrypt(data)
        encrypt_time = time.time() - start
        
        start = time.time()
        decrypted = context.decrypt(encrypted)
        decrypt_time = time.time() - start
        
        # Асинхронное шифрование/дешифрование
        start = time.time()
        encrypted_async = await context.encrypt_async(data)
        encrypt_async_time = time.time() - start
        
        start = time.time()
        decrypted_async = await context.decrypt_async(encrypted_async)
        decrypt_async_time = time.time() - start
        
        success = data == decrypted == decrypted_async
        
        return {
            'key_name': key_name,
            'mode': mode.name,
            'data_size': len(data),
            'success': success,
            'sync_encrypt': encrypt_time * 1000,
            'sync_decrypt': decrypt_time * 1000,
            'async_encrypt': encrypt_async_time * 1000,
            'async_decrypt': decrypt_async_time * 1000,
            'encrypted_size': len(encrypted)
        }
    
    async def run_demo(self):
        """Запускает демонстрацию"""
        print("ДЕМОНСТРАЦИЯ DEAL АЛГОРИТМА")
        print("=" * 50)
        
        test_dir = self.generate_test_files()
        
        test_files = [
            ('text.txt', 'Текстовый файл'),
            ('random_256.bin', 'Случайные данные 256B'),
            ('random_1024.bin', 'Случайные данные 1KB'), 
            ('random_4096.bin', 'Случайные данные 4KB'),
            ('test_image.bmp', 'BMP 32x32'),
            ('data.json', 'JSON файл')
        ]
        
        modes = [CipherMode.ECB, CipherMode.CBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR]
        results = []
        
        for filename, description in test_files:
            file_path = test_dir / filename
            if not file_path.exists():
                continue
                
            with open(file_path, 'rb') as f:
                data = f.read()
            
            print(f"\n{description} ({len(data)} байт)")
            print("-" * 40)
            
            for key_name, key_bytes in self.keys.items():
                for mode in modes:
                    result = await self.test_mode(data, mode, key_name, key_bytes)
                    results.append(result)
                    
                    file_size_kb = max(len(data) / 1024, 0.001)
                    speed_sync = result['sync_encrypt'] / file_size_kb
                    speed_async = result['async_encrypt'] / file_size_kb
                    
                    print(f"  {key_name}-{mode.name}: {'OK' if result['success'] else 'FAIL'}")
                    print(f"    Sync: {result['sync_encrypt']:.1f}мс ({speed_sync:.1f}мс/KB)")
                    print(f"    Async: {result['async_encrypt']:.1f}мс ({speed_async:.1f}мс/KB)")
        
        # Статистика
        print("\n" + "=" * 50)
        print("ИТОГИ")
        print("=" * 50)
        
        total = len(results)
        success = sum(1 for r in results if r['success'])
        print(f"Тестов: {total}, Успешно: {success}")
        
        for key_name in self.keys:
            key_results = [r for r in results if r['key_name'] == key_name]
            if key_results:
                avg_sync = sum(r['sync_encrypt'] for r in key_results) / len(key_results)
                avg_async = sum(r['async_encrypt'] for r in key_results) / len(key_results)
                speedup = avg_sync / avg_async if avg_async > 0 else 1
                print(f"{key_name}: ускорение {speedup:.1f}x")
        
        self.cleanup_directories()
        print("\nДемо завершено!")


if __name__ == "__main__":
    demo = DEALDemo()
    asyncio.run(demo.run_demo())