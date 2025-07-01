import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(__file__)


INPUT_DIR = os.path.join(BASE_DIR, 'inputFiles')
TEMP_DIR = os.path.join(BASE_DIR, 'tempFiles')
ENCRYPTED_DIR = os.path.join(BASE_DIR, 'encryptedFiles')
DECRYPTED_DIR = os.path.join(BASE_DIR, 'dptFiles')

os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

dotenv_path = os.path.join(os.path.dirname(__file__), 'key.env')
load_dotenv(dotenv_path=dotenv_path)

key_string = os.getenv("MASTER_KEY")
if not key_string:
    raise ValueError("MASTER_KEY not found in key.env")

MASTER_KEY = key_string.encode()
BLOCK_SIZE = 16
