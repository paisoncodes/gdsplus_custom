import frappe
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives import hashes as symmetric_hashes
from cryptography.exceptions import InvalidSignature

@frappe.whitelist()
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    # Serialize the public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

@frappe.whitelist()
def sign_data(private_key_pem, data, custom_salt_length):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=custom_salt_length,
        ),
        hashes.SHA256()
    )
    return signature

@frappe.whitelist()
def encrypt_data(public_key_pem, data):
    public_key = serialization.load_pem_public_key(public_key_pem)
    data_bytes = data.encode('utf-8')  # Encode data to bytes using UTF-8
    encrypted_data = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=symmetric_hashes.SHA256()),
            algorithm=symmetric_hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

@frappe.whitelist()
def verify_signature(public_key_pem, data, signature, custom_salt_length):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=custom_salt_length,
            ),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except InvalidSignature:
        return False  # Signature is invalid

@frappe.whitelist()
def decrypt_data(private_key_pem, encrypted_data):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=symmetric_hashes.SHA256()),
            algorithm=symmetric_hashes.SHA256(),
            label=None
        )
    )
    decrypted_text = decrypted_data.decode('utf-8')  # Decode decrypted data to UTF-8 text
    return decrypted_text

