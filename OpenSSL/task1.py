import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

'''Key Generation with OpenSSL and Python'''
'''======================================'''
# Load the private key from a PEM file
private_key_path = '/home/pingu/Documents/OpenSSL/private-key.pem'
with open(private_key_path, 'rb') as private_key_file:
    private_key = serialization.load_pem_private_key(
        private_key_file.read(),
        password=None,  # Replace with your password if your key is encrypted
        backend =  default_backend()
    )

# Extract the public key from the private key
public_key = private_key.public_key()

# Serialize the public key to PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the public key to a PEM file
public_key_path = '/home/pingu/Documents/OpenSSL/public_key.pem'
with open(public_key_path, 'wb') as public_key_file:
    public_key_file.write(public_key_pem)

print("Public key extracted and saved to 'public_key.pem'")


