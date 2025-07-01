import os
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# Load master key from .env file
dotenv_path = os.path.join(os.path.dirname(__file__), 'key.env')
load_dotenv(dotenv_path=dotenv_path)

key_string = os.getenv("MASTER_KEY")

if not key_string:
    raise ValueError("MASTER_KEY not found in key.env")

MASTER_KEY = key_string.encode()
BLOCK_SIZE = AES.block_size

# Create necessary directories
os.makedirs('os_project/inputFiles', exist_ok=True)
os.makedirs('os_project/tempFiles', exist_ok=True)
os.makedirs('os_project/encryptedFiles', exist_ok=True)
os.makedirs('os_project/dptFiles', exist_ok=True)

# Encrypt AES key using master key
def encrypt_aes_key(aes_key):
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(aes_key)
    return cipher.nonce + tag + ciphertext

# Decrypt AES key using master key
def decrypt_aes_key(encrypted_key):
    nonce = encrypted_key[:16]
    tag = encrypted_key[16:32]
    ciphertext = encrypted_key[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Encrypt multiple files
def encrypt_multiple_files():
    try:
        count = int(input("Enter the number of files to encrypt: "))
        file_names = []

        for i in range(count):
            name = input(f"Enter name of file {i+1} (from 'inputFiles/' folder): ")
            input_path = os.path.join('os_project/inputFiles', name)
            if not os.path.exists(input_path):
                print(f"File '{name}' not found. Skipping.")
                continue
            file_names.append(name)

        for name in file_names:
            input_path = os.path.join('os_project/inputFiles', name)
            temp_path = os.path.join('os_project/tempFiles', name)
            encrypted_path = os.path.join('os_project/encryptedFiles', name)

            shutil.move(input_path, temp_path)
            aes_key = get_random_bytes(16)
            iv = get_random_bytes(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)

            with open(temp_path, 'rb') as f:
                data = f.read()
            encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))
            encrypted_aes_key = encrypt_aes_key(aes_key)

            with open(encrypted_path, 'wb') as f:
                f.write(iv + encrypted_aes_key + encrypted_data)

            os.remove(temp_path)
            print(f"Encrypted and saved: {name}")

    except ValueError:
        print("Invalid input. Please enter a valid number.")

# Decrypt multiple files
def decrypt_multiple_files():
    try:
        count = int(input("Enter the number of files to decrypt: "))
        file_names = []

        for i in range(count):
            name = input(f"Enter name of file {i+1} (from 'encryptedFiles/' folder): ")
            encrypted_path = os.path.join('os_project/encryptedFiles', name)
            if not os.path.exists(encrypted_path):
                print(f"File '{name}' not found. Skipping.")
                continue
            file_names.append(name)

        for name in file_names:
            encrypted_path = os.path.join('os_project/encryptedFiles', name)
            decrypted_path = os.path.join('os_project/dptFiles', name)

            with open(encrypted_path, 'rb') as f:
                iv = f.read(16)
                encrypted_aes_key = f.read(48)
                encrypted_data = f.read()

            aes_key = decrypt_aes_key(encrypted_aes_key)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            os.remove(encrypted_path)
            print(f"Decrypted and saved: {name}")

    except ValueError:
        print("Invalid input. Please enter a valid number.")

# Main Menu
if __name__ == '__main__':
    while True:
        print("\n===== File Encryption/Decryption System =====")
        print("1. Encrypt Multiple Files")
        print("2. Decrypt Multiple Files")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            encrypt_multiple_files()
        elif choice == '2':
            decrypt_multiple_files()
        elif choice == '3':
            for filename in os.listdir('os_project/dptFiles'):
                src = os.path.join('os_project/dptFiles', filename)
                dest = os.path.join('os_project/inputFiles', filename)
                shutil.move(src, dest)
                print(f"Moved {filename} back to inputFiles.")
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
