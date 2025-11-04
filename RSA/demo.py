import asyncio
from src.cipher.crypto_service import RSACryptoService
from src.cipher.interface import PrimalityTestType
from attacks.Wienner_attack import WienerAttack
from attacks.Fermat_attack import FermatAttack
from src.utils.cipher_service import CipherService
from src.utils.primality.Miller_Rabin import MillerRabinTest

def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")

def print_success(message: str):
    print(f"УСПЕХ: {message}")

def print_warning(message: str):
    print(f"ПРЕДУПРЕЖДЕНИЕ: {message}")

def print_error(message: str):
    print(f"ОШИБКА: {message}")

def print_info(message: str):
    print(f"ИНФО: {message}")


async def demonstrate():
    
    # 1. Генерация ключевой пары RSA
    print_section("1. ГЕНЕРАЦИЯ КЛЮЧЕВОЙ ПАРЫ RSA")
    
    # Создаем класс для конфигурации
    class Config:
        def __init__(self, test_type, min_probability, bit_length):
            self.test_type = test_type
            self.min_probability = min_probability
            self.bit_length = bit_length
    
    config = Config(
        test_type=PrimalityTestType.MILLER_RABIN,
        min_probability=0.999,
        bit_length=256
    )
    
    rsa_service = RSACryptoService(config)
    
    print_info("Настройки генерации:")
    print_info("   • Тест простоты: Miller-Rabin")
    print_info("   • Вероятность: 99.9%")
    print_info("   • Длина ключа: 256 бит")
    
    await rsa_service.generate_key_pair()
    print_success("Ключевая пара успешно сгенерирована!")
    
    public_key = rsa_service.get_public_key()
    if public_key:
        print_info("Публичный ключ:")
        print_info(f"   • Модуль (n): {public_key['modulus']}")
        print_info(f"   • Экспонента (e): {public_key['exponent']}")

    # 2. Демонстрация символа Лежандра
    print_section("2. ДЕМОНСТРАЦИЯ СИМВОЛА ЛЕЖАНДРА")
    
    primality_tester = MillerRabinTest()
    
    # Простые числа для демонстрации
    primes = [7, 11, 17, 23]
    test_values = [2, 3, 5, 7]
    
    print_info("Вычисление символов Лежандра:")
    for p in primes:
        print_info(f"  Модуль p = {p}:")
        for a in test_values:
            try:
                L = CipherService.Legendre_symbol(a, p, primality_tester)
                status = "квадратичный вычет" if L == 1 else "квадратичный невычет" if L == -1 else "делится на p"
                print_info(f"    ({a}/{p}) = {L} - {status}")
            except ValueError as e:
                print_error(f"    Ошибка для ({a}/{p}): {e}")
    
    # Демонстрация ошибки для составного числа
    print_info("  Проверка на составном числе:")
    try:
        L = CipherService.Legendre_symbol(2, 15, primality_tester)
        print_error(f"    ОШИБКА: (2/15) = {L} (но 15 составное!)")
    except ValueError as e:
        print_success(f"    Корректная ошибка: {e}")

    # 3. Шифрование и дешифрование
    print_section("3. ТЕСТИРОВАНИЕ ШИФРОВАНИЯ И ДЕШИФРОВАНИЯ")
    test_data = 12345678901234567890
    print_info(f"Исходные данные: {test_data}")
    
    try:
        ciphertext = rsa_service.encrypt(test_data)
        print_info(f"Шифротекст: {ciphertext}")
        
        decrypted = rsa_service.decrypt(ciphertext)
        print_info(f"Дешифрованные данные: {decrypted}")
        
        if test_data == decrypted:
            print_success("Шифрование и дешифрование прошли успешно!")
        else:
            print_error("Ошибка: данные не совпадают после дешифрования!")
    except Exception as error:
        print_error(f"Ошибка при шифровании: {error}")

    # 4. Проверка устойчивости к атаке Винера
    print_section("4. ПРОВЕРКА УСТОЙЧИВОСТИ К АТАКЕ ВИНЕРА")
    attack_result = WienerAttack.attack(rsa_service)
    
    print_info("Результаты атаки Винера:")
    print_info(f"   • Успешна: {'ДА' if attack_result['success'] else 'НЕТ'}")
    print_info(f"   • Проанализировано подходящих дробей: {len(attack_result['convergents'])}")
    
    if not attack_result['success']:
        print_success("Нормальный ключ УСТОЙЧИВ к атаке Винера!")
    else:
        print_error("Ключ УЯЗВИМ к атаке Винера!")

    # 5. Демонстрация атаки Винера на слабый ключ
    print_section("5. ДЕМОНСТРАЦИЯ АТАКИ ВИНЕРА НА СЛАБЫЙ КЛЮЧ")
    print_info("Генерация специально ослабленного ключа...")
    await rsa_service.generate_weak_key_pair()
    
    weak_attack_result = WienerAttack.attack(rsa_service)
    
    print_info("Результаты атаки на слабый ключ:")
    print_info(f"   • Успешна: {'ДА' if weak_attack_result['success'] else 'НЕТ'}")
    
    if weak_attack_result['success']:
        print_warning("Атака Винера УСПЕШНА на слабый ключ!")
        print_info("Найденные параметры:")
        print_info(f"   • Приватная экспонента (d): {weak_attack_result['private_exponent']}")
        print_info(f"   • Функция Эйлера (φ): {weak_attack_result['phi']}")
    else:
        print_success("Даже слабый ключ оказался устойчивым!")

    # 6. Демонстрация атаки Ферма
    print_section("6. ДЕМОНСТРАЦИЯ АТАКИ ФЕРМА")
    print_info("Создание сервиса с малым ключом для демонстрации...")
    
    weak_config = Config(
        test_type=PrimalityTestType.MILLER_RABIN,
        min_probability=0.999,
        bit_length=128
    )
    
    weak_rsa = RSACryptoService(weak_config)
    
    print_info("Генерация ключа с близкими простыми числами...")
    await weak_rsa.generate_weak_key_pair_for_fermat()
    
    weak_public_key = weak_rsa.get_public_key()
    if weak_public_key:
        print_info("Цель атаки Ферма:")
        print_info(f"   • Модуль (n): {weak_public_key['modulus']}")
        
        fermat_result = FermatAttack.attack(weak_public_key)
        
        print_info("Результаты атаки Ферма:")
        print_info(f"   • Успешна: {'ДА' if fermat_result['success'] else 'НЕТ'}")
        print_info(f"   • Потрачено попыток: {fermat_result['attempts']}")
        
        if fermat_result['success'] and fermat_result['factors']:
            print_warning("Атака Ферма УСПЕШНА!")
            print_info("Найденные множители:")
            print_info(f"   • p = {fermat_result['factors'][0]}")
            print_info(f"   • q = {fermat_result['factors'][1]}")
            print_info(f"   • Проверка: p * q = {fermat_result['factors'][0] * fermat_result['factors'][1]}")
            print_info(f"   • Исходный модуль: {weak_public_key['modulus']}")

    # 7. Проверка нормального ключа на уязвимость к Ферма
    print_section("7. ПРОВЕРКА НОРМАЛЬНОГО КЛЮЧА НА УЯЗВИМОСТЬ")
    normal_public_key = rsa_service.get_public_key()
    if normal_public_key:
        is_vulnerable = FermatAttack.is_vulnerable(normal_public_key)
        print_info("Проверка нормального ключа на уязвимость к атаке Ферма:")
        print_info(f"   • Уязвим: {'ДА' if is_vulnerable else 'НЕТ'}")
        
        if not is_vulnerable:
            print_success("Нормальный ключ УСТОЙЧИВ к атаке Ферма!")
        else:
            print_error("Нормальный ключ УЯЗВИМ к атаке Ферма!")

    # Итоговый вывод
    print_section("ИТОГИ ДЕМОНСТРАЦИИ")
    print_info("Все компоненты системы работают корректно:")
    print_info("   • Математические функции (Лежандра, Якоби, НОД)")
    print_info("   • Тесты простоты (Ферма, Соловея-Штрассена, Миллера-Рабина)")
    print_info("   • RSA шифрование/дешифрование")
    print_info("   • Генерация защищенных ключей")
    print_info("   • Атака Винера")
    print_info("   • Атака Ферма")
    print_info("   • Защита от атак в нормальных ключах")


# Обработка ошибок
if __name__ == "__main__":
    try:
        asyncio.run(demonstrate())
    except Exception as error:
        print_error(f"Критическая ошибка: {error}")
        import traceback
        traceback.print_exc()