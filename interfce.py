import os
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# Load MASTER_KEY from key.env
dotenv_path = os.path.join(os.path.dirname(__file__), 'key.env')
load_dotenv(dotenv_path)
key_string = os.getenv("MASTER_KEY")
if not key_string:
    raise ValueError("MASTER_KEY not found in key.env")
MASTER_KEY = key_string.encode()
BLOCK_SIZE = AES.block_size

# Ensure directories exist
os.makedirs('os_project/inputFiles', exist_ok=True)
os.makedirs('os_project/tempFiles', exist_ok=True)
os.makedirs('os_project/encryptedFiles', exist_ok=True)
os.makedirs('os_project/dptFiles', exist_ok=True)

# AES Key Encryption
def encrypt_aes_key(aes_key):
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(aes_key)
    return cipher.nonce + tag + ciphertext

def decrypt_aes_key(encrypted_key):
    nonce = encrypted_key[:16]
    tag = encrypted_key[16:32]
    ciphertext = encrypted_key[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# GUI App
class FileCryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES File Encryption/Decryption")
        self.geometry("600x400")
        self.configure(bg="#1e1e1e")
        self.dark_mode = True

        self.build_ui()

    def build_ui(self):
        title = tk.Label(self, text="AES File Encryption/Decryption", font=("Segoe UI", 20, "bold"), fg="white", bg="#1e1e1e")
        title.pack(pady=30)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)

        ttk.Style().configure("TButton", font=("Segoe UI", 12), padding=10)

        ttk.Button(btn_frame, text="Encrypt Files", command=self.encrypt_files).grid(row=0, column=0, padx=20, pady=10)
        ttk.Button(btn_frame, text="Decrypt Files", command=self.decrypt_files).grid(row=0, column=1, padx=20, pady=10)
        ttk.Button(btn_frame, text="Exit", command=self.exit_app).grid(row=0, column=2, padx=20, pady=10)

        self.status_bar = tk.Label(self, text="Welcome! Choose an option.", bg="#1e1e1e", fg="white", anchor="w")
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def encrypt_files(self):
        try:
            count = simpledialog.askinteger("Encrypt Files", "Enter number of files to encrypt:")
            if count is None or count <= 0:
                return

            file_names = []
            for i in range(count):
                name = simpledialog.askstring("Encrypt", f"Enter file name {i+1} (in inputFiles/):")
                if not name:
                    continue
                path = os.path.join('os_project/inputFiles', name)
                if not os.path.exists(path):
                    messagebox.showwarning("Missing", f"File '{name}' not found.")
                    continue
                file_names.append(name)

            for name in file_names:
                self.encrypt_file(name)

            self.status_bar.config(text="Encryption completed.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def encrypt_file(self, name):
        input_path = os.path.join('os_project/inputFiles', name)
        temp_path = os.path.join('os_project/tempFiles', name)
        enc_path = os.path.join('os_project/encryptedFiles', name)

        shutil.move(input_path, temp_path)
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        with open(temp_path, 'rb') as f:
            data = f.read()
        enc_data = cipher.encrypt(pad(data, BLOCK_SIZE))
        enc_key = encrypt_aes_key(aes_key)

        with open(enc_path, 'wb') as f:
            f.write(iv + enc_key + enc_data)

        os.remove(temp_path)

    def decrypt_files(self):
        try:
            count = simpledialog.askinteger("Decrypt Files", "Enter number of files to decrypt:")
            if count is None or count <= 0:
                return

            file_names = []
            for i in range(count):
                name = simpledialog.askstring("Decrypt", f"Enter file name {i+1} (in encryptedFiles/):")
                if not name:
                    continue
                path = os.path.join('os_project/encryptedFiles', name)
                if not os.path.exists(path):
                    messagebox.showwarning("Missing", f"File '{name}' not found.")
                    continue
                file_names.append(name)

            for name in file_names:
                self.decrypt_file(name)

            self.status_bar.config(text="Decryption completed.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self, name):
        enc_path = os.path.join('os_project/encryptedFiles', name)
        dec_path = os.path.join('os_project/dptFiles', name)

        with open(enc_path, 'rb') as f:
            iv = f.read(16)
            enc_key = f.read(48)
            enc_data = f.read()

        aes_key = decrypt_aes_key(enc_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        dec_data = unpad(cipher.decrypt(enc_data), BLOCK_SIZE)

        with open(dec_path, 'wb') as f:
            f.write(dec_data)

    def exit_app(self):
        for fname in os.listdir('os_project/dptFiles'):
            src = os.path.join('os_project/dptFiles', fname)
            dst = os.path.join('os_project/inputFiles', fname)
            shutil.move(src, dst)
        self.status_bar.config(text="Files moved to inputFiles. Exiting...")
        self.after(1000, self.destroy)

if __name__ == "__main__":
    app = FileCryptoApp()
    app.mainloop()
