import numpy
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


key = "key"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt="salt".encode(),
    iterations=1,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
f = Fernet(key)

message = """
TOP SECRET
"""
encrypted = f.encrypt(message.encode())
print(encrypted.decode())

decrypted = f.decrypt(encrypted)
print(decrypted.decode())
