from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

''' Secure Data Transmission with Python'''
'''====================================='''

# Load student B's private key
with open("private-key.pem", "rb") as private_key_file:
    private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

# Read the encrypted data from a file
with open("encrypted_data.bin", "rb") as file:
    encrypted_data = file.read()

# Decrypt the data
plaintext = private_key.decrypt(
    encrypted_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the decrypted data to a file
with open("decrypted_text.txt", "wb") as file:
    file.write(plaintext)
