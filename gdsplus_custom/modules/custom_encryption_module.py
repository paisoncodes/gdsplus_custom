import frappe
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import requests
import base64
import logging
from datetime import datetime, timedelta


MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117

@frappe.whitelist()
def get_start_and_end_timestamps(no_of_days: int) -> tuple:
    now_datetime = datetime.now()

    one_day_timedelta = timedelta(days=no_of_days)

    start_datetime = now_datetime.replace(hour=0, minute=0, second=0, microsecond=0) - one_day_timedelta
    end_datetime = now_datetime.replace(hour=23, minute=59, second=59, microsecond=0) - one_day_timedelta

    start_timestamp = str(start_datetime.timestamp() * 1000).split('.')[0]
    end_timestamp = str(end_datetime.timestamp() * 1000).split('.')[0]

    return start_timestamp, end_timestamp

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
    response = requests.post(url, json=body, params=params, headers=headers)
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


def sign_data(data, private_key):
    key_bytes = base64.b64decode(private_key)
    private_key = serialization.load_pem_private_key(key_bytes, password=None, backend= default_backend())

    signature = private_key.sign(data.encode('utf-8'), padding.PKCS1v15(), hashes.SHA256())
    signed_data = base64.b64encode(signature).decode('utf-8')

    return signed_data


def verify_signature(data, signature, public_key):
    try:
        key_bytes = base64.b64decode(public_key)
        public_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())

        public_key.verify(
            base64.b64decode(signature),
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def encrypt_data(data, public_key):
    try:
        rsa_key_bytes = base64.b64decode(public_key)
        key = serialization.load_pem_public_key(rsa_key_bytes)
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        input_bytes = data.encode()
        input_length = len(input_bytes)
        offset = 0
        result_bytes = bytearray()

        while input_length - offset > 0:
            if input_length - offset > MAX_ENCRYPT_BYTE:
                cache = key.encrypt(input_bytes[offset:offset + MAX_ENCRYPT_BYTE],
                                    padding.PKCS1v15())
                offset += MAX_ENCRYPT_BYTE
            else:
                cache = key.encrypt(input_bytes[offset:], padding.PKCS1v15())
                offset = input_length
            result_bytes.extend(cache)

        return base64.b64encode(result_bytes).decode()
    except Exception as e:
        logging.exception(e)
        frappe.throw(str(e))


def decrypt_data(data, private_key):
    key_bytes = base64.b64decode(private_key)
    key = serialization.load_pem_private_key(key_bytes, password=None)
    encrypted_data = base64.b64decode(data)
    input_len = len(encrypted_data)
    out = bytearray()
    offset = 0
    i = 0

    while input_len - offset > 0:
        if input_len - offset > MAX_DECRYPT_TYPE:
            cache = key.decrypt(encrypted_data[offset:offset + MAX_DECRYPT_TYPE],
                                padding.PKCS1v15())
        else:
            cache = key.decrypt(encrypted_data[offset:], padding.PKCS1v15())
        out.extend(cache)
        i += 1
        offset = i * MAX_DECRYPT_TYPE

    return out.decode()


def json_dumps(json_data):
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def signature_content(response_content):
    """
    Generate Signature content
    :param response_content: opay response
    :return: Signature content
    """
    res_data = {
        'code': response_content['code'],
        'message': response_content['message'],
        'data': response_content['data'],
        'timestamp': response_content['timestamp'],
    }

    sorted_params = dict(sorted(res_data.items()))
    content = []
    keys = list(sorted_params.keys())
    keys.sort()
    for key in keys:
        value = sorted_params[key]
        if key is None or key == "":
            continue
        if value is None:
            continue
        if key == "sign":
            continue
        content.append(f"{key}={value}")
    return "&".join(content)

@frappe.whitelist()
def build_request_body(request_content, timestamp, opay_public_key, merc_private_key):
    """
    Build request body
    :param request_content: request content
    :return: request ciphertext
    """
    # encrypt
    enc_data = encrypt_data(json_dumps(request_content), opay_public_key)

    # generate sign
    sign = sign_data(enc_data + timestamp, merc_private_key)

    return {"paramContent": enc_data, "sign": sign}

@frappe.whitelist()
def analytic_response(response_content, opay_public_key, merc_private_key):
    """
    Analytic response
    :param response_content: opay api response
    :return: Decrypted text
    :raise Exception: Opay api call failed, response code is not 00000 or verify signature failed
    """
    if response_content['code'] != '00000':
        raise Exception(f"Opay api call failed, response code is not 00000, response: {response_content}")

    enc_text = response_content['data']

    # verify signature
    sign_content = signature_content(response_content)
    sign = response_content['sign']
    verift = verify_signature(sign_content, sign, opay_public_key)
    if not verift:
        raise Exception(f"Opay api call error, verify signature failed, response: {response_content}")

    # decrypt
    return decrypt_data(enc_text, merc_private_key)
