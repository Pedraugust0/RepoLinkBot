from config import ENCRYPTION_KEY
from cryptography.fernet import Fernet
from dotenv import load_dotenv

_cipher_suite = None

def get_cipher_suite():
    global _cipher_suite
    if _cipher_suite is None:
        if not ENCRYPTION_KEY:
            raise ValueError("Encryption key (APP_ENCRYPTION_KEY) is missing for cipher suite.")

        _cipher_suite = Fernet(ENCRYPTION_KEY.encode())
    return _cipher_suite

def encrypt_data(data: str) -> bytes:
    """Criptografa uma string."""
    cipher_suite = get_cipher_suite()
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    """Descriptografa bytes para uma string."""
    cipher_suite = get_cipher_suite()
    return cipher_suite.decrypt(encrypted_data).decode()