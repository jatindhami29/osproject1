import os
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from masterKey import INPUT_DIR, TEMP_DIR, ENCRYPTED_DIR, MASTER_KEY, BLOCK_SIZE

def encrypt_aes_key(aes_key):
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(aes_key)  #encrypt() → encrypts the file’s AES key.  digest() → generates a tag to verify authenticity.   
    return cipher.nonce + tag + ciphertext  #Nonce (Number used once)   48 byte total 

def encrypt_multiple_files():
    try:
        count = int(input("Enter the number of files to encrypt: "))
        file_names = []

        for i in range(count):
            name = os.path.basename(input(f"Enter name of file {i+1} (from 'inputFiles/' folder): ").strip())
            name = os.path.basename(name)
            input_path = os.path.join(INPUT_DIR, name)
            if not os.path.exists(input_path):
                print(f"File '{name}' not found. Skipping.")
                continue
            file_names.append(name)

        for name in file_names:
            input_path = os.path.join(INPUT_DIR, name)
            temp_path = os.path.join(TEMP_DIR, name)
            encrypted_path = os.path.join(ENCRYPTED_DIR, name)

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
