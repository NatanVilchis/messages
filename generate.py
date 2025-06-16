from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64 

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=13,
    salt=hashlib.sha512("HELLO".encode()).digest(),
    iterations=13,
    backend=default_backend()
)
key = hashlib.sha512("WORLD".encode()).digest()
key = base64.urlsafe_b64encode(key)
print(key)
f = Fernet(key)
