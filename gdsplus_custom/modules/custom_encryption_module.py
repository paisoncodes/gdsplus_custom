import frappe
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import json
import requests

@frappe.whitelist()
def make_custom_request(url, method, params=None, headers=None, body=None):
    response = "None"
    try:
        if method.upper() == "POST":
            response = make_custom_post_request(url, params, headers, body)
        elif method.upper() == "GET":
            response = make_custom_get_request(url, params, headers, body)
        elif method.upper() == "PUT":
            response = make_custom_put_request(url, params, headers, body)
        elif method.upper() == "DELETE":
            response = make_custom_delete_request(url, params, headers, body)
    except Exception as e:
        response = e

    return dict(json.loads(json.dumps(response.json())))

def make_custom_post_request(url, params, headers, body):
    response = requests.post(url, data=body, params=params, headers=headers)
    return response

def make_custom_get_request(url, params, headers, body):
    response = requests.get(url, data=body, params=params, headers=headers)
    return response

def make_custom_put_request(url, params, headers, body):
    response = requests.put(url, data=body, params=params, headers=headers)
    return response

def make_custom_delete_request(url, params, headers, body):
    response = requests.delete(url, data=body, params=params, headers=headers)
    return response

@frappe.whitelist()
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=8192,
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
def sign_data(private_key_pem, data, timestamp):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        (data+timestamp).encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

@frappe.whitelist()
def encrypt_data(public_key_pem, data):
    public_key = serialization.load_pem_public_key(public_key_pem)
    if isinstance(data, dict):
        data = json.dumps(data)
    data_bytes = data.encode('utf-8')
    encrypted_data = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data.hex()

@frappe.whitelist()
def verify_signature(public_key_pem, data, signature, timestamp):
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            bytes.fromhex(signature),
            (data + timestamp).encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

@frappe.whitelist()
def decrypt_data(private_key_pem, encrypted_data):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    decrypted_data = private_key.decrypt(
        bytes.fromhex(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted_text = decrypted_data.decode('utf-8')
    try:
        decrypted_text = dict(json.loads(decrypted_text))
    except Exception as _:
        pass
    return decrypted_text
