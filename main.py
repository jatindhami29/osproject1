import os
import shutil
from masterKey import DECRYPTED_DIR, INPUT_DIR
from encrypt import encrypt_multiple_files
from decrypt import decrypt_multiple_files

def move_decrypted_back_to_input():
    for filename in os.listdir(DECRYPTED_DIR):
        src = os.path.join(DECRYPTED_DIR, filename)
        dest = os.path.join(INPUT_DIR, filename)
        shutil.move(src, dest)
        print(f"Moved {filename} back to inputFiles.")

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
            move_decrypted_back_to_input()
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
