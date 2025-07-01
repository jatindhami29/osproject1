import os
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from masterKey import ENCRYPTED_DIR, DECRYPTED_DIR, INPUT_DIR, MASTER_KEY, BLOCK_SIZE

def decrypt_aes_key(encrypted_key):
    nonce = encrypted_key[:16]
    tag = encrypted_key[16:32]
    ciphertext = encrypted_key[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_multiple_files():
    try:
        count = int(input("Enter the number of files to decrypt: "))
        file_names = []

        for i in range(count):
            name = os.path.basename(input(f"Enter name of file {i+1} (from 'encryptedFiles/' folder): ").strip())
            encrypted_path = os.path.join(ENCRYPTED_DIR, name)
            if not os.path.exists(encrypted_path):
                print(f"File '{name}' not found. Skipping.")
                continue
            file_names.append(name)

        for name in file_names:
            encrypted_path = os.path.join(ENCRYPTED_DIR, name)
            decrypted_path = os.path.join(DECRYPTED_DIR, name)

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
