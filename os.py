import os
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Constants
MASTER_KEY = b'Sixteen byte key'  # 16 bytes master key (should be stored securely)
BLOCK_SIZE = AES.block_size
KEY_SIZE = 16  # AES-128
NONCE_SIZE = 16
TAG_SIZE = 16

# Directory paths
DIRECTORIES = {
    'input': 'inputFiles',
    'temp': 'tempFiles',
    'encrypted': 'encryptedFiles',
    'decrypted': 'dptFiles'
}

# File paths
FILE_NAME = 'osPro.pdf'
FILE_PATHS = {
    'input': os.path.join(DIRECTORIES['input'], FILE_NAME),
    'temp': os.path.join(DIRECTORIES['temp'], FILE_NAME),
    'encrypted': os.path.join(DIRECTORIES['encrypted'], FILE_NAME),
    'decrypted': os.path.join(DIRECTORIES['decrypted'], FILE_NAME)
}


def setup_directories():
    """Create all required directories if they don't exist."""
    for directory in DIRECTORIES.values():
        os.makedirs(directory, exist_ok=True)


def encrypt_aes_key(aes_key):
    """Encrypt AES key using master key with EAX mode."""
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(aes_key)
    return cipher.nonce + tag + ciphertext  # 16 + 16 + 16 = 48 bytes


def decrypt_aes_key(encrypted_key):
    """Decrypt AES key using master key with EAX mode."""
    nonce = encrypted_key[:NONCE_SIZE]
    tag = encrypted_key[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_key[NONCE_SIZE + TAG_SIZE:]
    
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_file():
    """Encrypt the input file and store it in the encrypted directory."""
    if not os.path.exists(FILE_PATHS['input']):
        print("Error: Input file not found!")
        return False

    try:
        # Step 1: Move input file to temp folder
        shutil.move(FILE_PATHS['input'], FILE_PATHS['temp'])
        print("Moved input file to secure temp folder.")

        # Step 2: Generate AES key and IV
        aes_key = get_random_bytes(KEY_SIZE)
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Step 3: Read and encrypt file content
        with open(FILE_PATHS['temp'], 'rb') as f:
            data = f.read()
        
        encrypted_data = cipher.encrypt(pad(data, BLOCK_SIZE))

        # Step 4: Encrypt AES key
        encrypted_aes_key = encrypt_aes_key(aes_key)

        # Step 5: Write encrypted output
        with open(FILE_PATHS['encrypted'], 'wb') as f:
            f.write(iv + encrypted_aes_key + encrypted_data)
        print(f"Encryption complete. File saved to '{DIRECTORIES['encrypted']}'.")

        # Step 6: Delete original moved file
        os.remove(FILE_PATHS['temp'])
        print("Original file deleted from temp folder.")
        return True

    except Exception as e:
        print(f"Error during encryption: {str(e)}")
        return False


def decrypt_file():
    """Decrypt the encrypted file and store it in the decrypted directory."""
    if not os.path.exists(FILE_PATHS['encrypted']):
        print("Error: Encrypted file not found!")
        return False

    try:
        with open(FILE_PATHS['encrypted'], 'rb') as f:
            iv = f.read(BLOCK_SIZE)
            encrypted_aes_key = f.read(NONCE_SIZE + TAG_SIZE + KEY_SIZE)
            encrypted_data = f.read()

        aes_key = decrypt_aes_key(encrypted_aes_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)

        with open(FILE_PATHS['decrypted'], 'wb') as f:
            f.write(decrypted_data)
        print(f"Decryption complete. File saved to '{DIRECTORIES['decrypted']}'.")
        return True

    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        return False


def main():
    """Main function to handle user interaction."""
    setup_directories()
    
    print("\nFile Encryption/Decryption Tool")
    print("1. Encrypt File")
    print("2. Decrypt File")
    
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == '1':
        if encrypt_file():
            print("Operation completed successfully.")
    elif choice == '2':
        if decrypt_file():
            print("Operation completed successfully.")
    else:
        print("Invalid choice. Please enter 1 or 2.")


if __name__ == '__main__':
    main()