import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

''' Secure Email Communication with Python'''
'''========================================'''

# Load Computer B's private key and Computer A's public key
with open("studentB_private.pem", "rb") as private_key_file:
    recipient_private_key = serialization.load_pem_private_key(private_key_file.read(), password=None, backend=default_backend())

with open("studentA_public.pem", "rb") as public_key_file:
    sender_public_key = serialization.load_pem_public_key(public_key_file.read(), backend=default_backend())

# Email configuration
recipient_email = "recipient@example.com"

# Connect to the email server and retrieve emails
try:
    server = smtplib.SMTP("imap.example.com")
    server.login(recipient_email, "your_password")
    server.select("inbox")

    # Fetch the email with the encrypted message
    typ, data = server.search(None, 'ALL')
    for num in data[0].split():
        typ, msg_data = server.fetch(num, '(RFC822)')
        email_data = msg_data[0][1]

        # Parse the email content
        msg = email.message_from_bytes(email_data)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
                    continue
                if part.get_filename() == "encrypted_message.bin":
                    # Decrypt the message using recipient's private key
                    ciphertext = part.get_payload(decode=True)
                    decrypted_message = recipient_private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print("Received secure email content:")
                    print(decrypted_message.decode('utf-8'))
except Exception as e:
    print(f"An error occurred: {str(e)}")
