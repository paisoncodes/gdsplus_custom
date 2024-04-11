"""
Opay encryption and decryption tool example

requirements: pycryptodome>=3.15.0
"""

__author__ = 'hao.zheng'

# import frappe

import base64
import json
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117


def encrypt_by_public_key(input_str, public_key):
    """
    Encrypt with public key
    :param input_str: Need to encrypt content
    :param public_key: public key
    :return: Ciphertext
    """
    rsa_key_bytes = base64.b64decode(public_key)
    key = RSA.import_key(rsa_key_bytes)
    cipher = PKCS1_v1_5.new(key)
    input_bytes = input_str.encode()
    input_length = len(input_bytes)
    offset = 0
    result_bytes = bytearray()
    while input_length - offset > 0:
        if input_length - offset > MAX_ENCRYPT_BYTE:
            cache = cipher.encrypt(input_bytes[offset:offset + MAX_ENCRYPT_BYTE])
            offset += MAX_ENCRYPT_BYTE
        else:
            cache = cipher.encrypt(input_bytes[offset:])
            offset = input_length
        result_bytes.extend(cache)

    return base64.b64encode(result_bytes).decode()


def decrypt_by_private_key(text, private_key):
    """
    Decrypt with private key
    :param text: Ciphertext
    :param private_key: private key
    :return: Decrypted text
    """
    key_bytes = base64.b64decode(private_key)
    key = RSA.import_key(key_bytes)
    cipher = PKCS1_v1_5.new(key)
    encrypted_data = base64.b64decode(text)  # Base64 Decode
    input_len = len(encrypted_data)
    out = bytearray()
    offset = 0
    i = 0
    while input_len - offset > 0:
        if input_len - offset > MAX_DECRYPT_TYPE:
            cache = cipher.decrypt(encrypted_data[offset:offset + MAX_DECRYPT_TYPE], None)
        else:
            cache = cipher.decrypt(encrypted_data[offset:], None)
        out.extend(cache)
        i += 1
        offset = i * MAX_DECRYPT_TYPE
    return out.decode()


def generate_sign(data, private_key):
    """
    Generate a signature
    :param data: Signature data
    :param private_key: Private key
    :return: signature
    """
    key_bytes = base64.b64decode(private_key)
    rsa_key = RSA.import_key(key_bytes)

    signer = pkcs1_15.new(rsa_key)
    digest = SHA256.new(data.encode('utf-8'))

    signature = signer.sign(digest)
    signed_data = base64.b64encode(signature).decode('utf-8')

    return signed_data


def verify_signature(data, signature, public_key):
    """
    Verify the signature
    :param data: Verify the data
    :param signature: signature
    :param public_key: Public key
    :return: True or False
    """
    try:
        key_bytes = base64.b64decode(public_key)
        rsa_key = RSA.import_key(key_bytes)

        verifier = pkcs1_15.new(rsa_key)
        hashed_data = SHA256.new(data.encode('utf-8'))

        verifier.verify(hashed_data, base64.b64decode(signature))
        return True
    except Exception:
        return False


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

# @frappe.whitelist()
def build_request_body(request_content, timestamp, opay_public_key, merc_private_key):
    """
    Build request body
    :param request_content: request content
    :return: request ciphertext
    """
    # encrypt
    enc_data = encrypt_by_public_key(json_dumps(request_content), opay_public_key)

    # generate sign
    sign = generate_sign(enc_data + timestamp, merc_private_key)

    return {"paramContent": enc_data, "sign": sign}

# @frappe.whitelist()
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
    return decrypt_by_private_key(enc_text, merc_private_key)



data = {
  "data": "Tt3DFVHEkw9EiP4JIGQnOApliLDGkzywkM+CKz+Blg0mmoLlAG1XOruUf3XHcPGYR5fXQhPOldEf0w5/j7J+l0Paro2SDRJKLdeH6SY9JaJrmmgghjhQ+jgKbG03gRHNoXtg4FiW4c5N7M1KCM4nxNdaHihvUWbkqa2zO8s4pYFw3Qk+2D9SF1O5DiNB8AHmlp1q+7lB/PzQi/cwT+yUzkFMQi5V8JDhkYHPwprkbR0VHIdi8SM6swekyzycYpXiKdZpSjQg0XzuwLNX9QqU83ypz0JQ+qDxKPvlo9NjmYC8C2sHWwFnjyCJ/r/JKU6Jg4kOEbDDFldceBwZotpixlMuV024bOl0hgD6qq32GdyTumb8WgLuyvf+85hXKSsVx6AYWgYmxxF/PAgpaHztoRvyKBm2eBmBdhWovXKYa/PZS0ig+oqemmXjA0YH2seVuezlkdA8z8G88Ch5VqeonN8z8C+BycM1IUK6MbQIi7iHAncWA5D77V8Am+ws3xOKQcM9nWKalos9A9TSmq+VdYwj7fRObmZ7+w/7EDC4VtRNgM/CrCgDVAbfQAjJgB8iv81DqHTpIv49qKBJ+91eABOp7vLyKd44y1mUCQ71F5k1JeapY11cIRseAKe1HvJttcDV5Jay546bvEUy7bWrh+MlD4IL/nQODxh98p85QD0FTLVavTT3fyj1NFsxZU+xn21ZQ65YHUhYB/bcPG2+jJuSMInwu3JTuGba7scjcRWi6mDhZBiL0CttyCgMeEp1T6WVxtveeWcPhdKb4i1uJGAn6unItRBW6/WcK6jblqx/jZFutjzMzVjGwrC/TDulPiUzXBchHXIg/4Z0n+ZdOwgUfRXQImUzrZy7rckTqQK5f3FgPLTQWIRLEHpnEeTbybKibTVSJCUVL/GBddkNV5n8Gd7aF8K4jhHbLmtrcUM06yg/7IfoyaNCSsRHH1506fTaDwDSm6B/vW7SP5sddcinPZFlYmD/32KRX5rrhmcasRQyj8vYAKZ/rhH6P/vXokBsOtcmAjtB44sl5g9UZkCJmRDxdSTKwpRRv5IWjzHGsZhFHG1SRRoXuoUeWEHVkSIX1461mArNH6Oy1sCR677bcIdq6wit4PZnTzJzaXu43X826GviAy4rWfKrDKJ9+q0uRFX8Prgl9biZMwwewMs4VixodbcZv8miEIqJQvE=",
  "cmd": "opay-notify"
}
MERC_PRIVATE_KEY = """MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKsMM030G3ZgHRjYBInUXbp8VAe3TV7I2Xu4szoCmVLby6OfIUvLAM21EskqsXywLuKZxezpoLjIHbVpfdiyQngypzBn4+8WtHOwCnvWFRBT9boTA6vz+Fxt+NfgzgkVwM/1cwSVNPuqb5ABzD1ddgQTTumcx/eQ/BaIbQ2lnopfAgMBAAECgYAs3L1UE9NkH99h1b6S++09bUCI6Y3Ub2+DYLU5YNcgAWAO4TzVaUAjs/tiYd09a+RQMK7V7YznCi2omCuWu2JtQGxJh7uEUWJaFqkylFPy9JJF1zR2T3YuBdAuXRQ9w9ayRcGv+z2xmzSav8qrIsTZJvgNplTY92zBU2UfjUpyOQJBANQuMOi6tAWbtaMS8ZNOU+9O+f/jNiXLgrDTln9CQWKpQ2vikOSUFWVhSBOda2K08PvPbVJEt+Q3fB9Qnw3DSv0CQQDOX1pBgJgAik+tNsnCAF5ZdpCDcng4HlKJvvN4ePy0FT0mTSc6pii5k9CCrV6FQvmCBryb+Kmi4g0DCnyG8A+LAkAqw9iVv7OzAaw9Xv8TupDORfO7cHckbP09WJgXtCnrkcQGBZdAitw5H79gPLU9Is0DY85b63/I3qoEwcIdCwSdAkEArB8TI/ag0DKLaah8dfXguzUMKtXaNtPzezdr0Vr3SSs9qShIQ7450S3bhmIap4LInw4HWP74XQW0XIjue4zVKQJBAId0bhsGjoqzyQ8D+WUXPs/Y+/XvpHCRl4oj6eZkvqwGRPCLzj0KPeUMoOmfxNlS2Xm7/BHrXVxtOeZk7KY5ZOI="""

# print(decrypt_by_private_key(data['data'], MERC_PRIVATE_KEY))