# Импорт необходимых библиотек
import os
import sqlite3
import sys
import ast
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

conn = sqlite3.connect('passwords_db.db')
cursor = conn.cursor()
conn.commit()
os.system('cls' if os.name == 'nt' else 'clear')
print("База данных Passwords_db была успешно создана/подключена!")
input()

def check_db_exists():
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'")
    table_exists = cursor.fetchall()
    if table_exists:
        print("База данных инициализированна!")
        cursor.execute("DELETE FROM passwords;"); conn.commit()
        cursor.execute("INSERT INTO passwords (salt, iv, ciphered_bytes) VALUES (NULL, NULL, NULL);"); conn.commit()
        input()
        return
    print("Создание необходимых таблиц!")
    createTable = """CREATE TABLE passwords (
                  salt TEXT,
                  iv TEXT,
                  ciphered_bytes TEXT)"""
    cursor.execute(createTable); conn.commit()
    cursor.execute("INSERT INTO passwords (salt, iv, ciphered_bytes) VALUES (NULL, NULL, NULL);"); conn.commit()
    input()

check_db_exists()

password = input("Введите свой мастер-ключ: ")
if not(password):
    os.system('cls' if os.name == 'nt' else 'clear')
    input("Ошибка! Мастер-ключ не может быть пустым! нажмите Enter.")
    sys.exit()
else:
    pass
    
def main ():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("1. Зашифровать мастер-ключ\n"
          "2. Зашифровать данные\n")
    action = int(input("Выберите действие: "))
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"Вы выбрали действие: №{action}\n")
        
    if action == 1:
        def passwordShifrate(password):
            password = password.encode('utf-8')
            salt = get_random_bytes(32)
            cursor.execute(f"UPDATE passwords SET salt = '{list(salt)}';"); conn.commit()
            key = PBKDF2(password, salt, dkLen=32)
            cipher_encrypt = AES.new(key, AES.MODE_CFB)
            ciphered_bytes = cipher_encrypt.encrypt(password)
            cursor.execute(f"UPDATE passwords SET ciphered_bytes = '{list(ciphered_bytes)}';"); conn.commit()
            iv = cipher_encrypt.iv
            cursor.execute(f"UPDATE passwords SET iv = '{list(iv)}';"); conn.commit()
            input("Ваш мастер-ключ успешно зашифрован!")
            main()
        passwordShifrate(password)
    elif action == 2:
        cursor.execute("SELECT salt FROM passwords"); conn.commit()
        a = cursor.fetchall()
        if a == [(None,)]:
            input("Вы не зашифровали свой мастер-ключ!")
            main()
        else:
            data = input("Введите то, что хотите зашифровать: ")
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Данные зашифрованны.")
            def passwordDecrypt():
                try:
                    passwordDecrypt = input("Введите ваш мастер-ключ для расшифровки: ").encode('utf-8')
                    cursor.execute("SELECT salt FROM passwords;"); saltDecrypt = bytes(ast.literal_eval(str(cursor.fetchall())[3:-4]))
                    keyDecrypt = PBKDF2(passwordDecrypt, saltDecrypt, dkLen=32)
                    cursor.execute("SELECT iv FROM passwords"); ivDecrypt = bytes(ast.literal_eval(str(cursor.fetchall())[3:-4]))
                    cursor.execute("SELECT ciphered_bytes FROM passwords"); DecryptedBytes = bytes(ast.literal_eval(str(cursor.fetchall())[3:-4]))
                    cipher_decrypt = AES.new(keyDecrypt, AES.MODE_CFB, iv=ivDecrypt)
                    deciphered_bytes = cipher_decrypt.decrypt(DecryptedBytes)
                    decrypted_data = deciphered_bytes.decode('utf-8')
                    if decrypted_data == password:
                        print("Данные успешно расшифрованны:", data)
                        input()
                        os.system('cls' if os.name == 'nt' else 'clear')
                        sys.exit()
                except Exception as e:
                    print("Ошибка! Скорее всего Вы ввели неправильный мастер-ключ!")
                    input()
                    main()
            
        passwordDecrypt()
        
if __name__ == '__main__': 
    main()
