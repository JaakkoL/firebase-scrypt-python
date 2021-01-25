"""Python implementation of Firebase's customized scrypt password hashing algorithm

See: https://github.com/firebase/scrypt/issues/2#issuecomment-548203625

1. Decrypt the User's salt, and Project's base64_signer_key and base64_salt_separator from base64.

2. Run scrypt function with the parameters:
    password = User's password
    salt = User's salt + salt_separator
    options.N = 2 ^ mem_cost
    options.r = rounds
    options.p = 1

    This generates a derived key used in encryption.

3. Take the returned derived key, and run AES on it, with the key being the derived key, and the input being the project's signer_key (decrypted from base64).

4. Encode the result using base64 to finalize hash creation
"""

import base64
import hashlib
from Crypto.Cipher import AES

class InvalidPassword(Exception):
    pass

def generate_derived_key(
        password: str,
        salt: str,
        salt_separator: str,
        rounds: int,
        mem_cost: int
) -> bytes:
    """Generates derived key from known parameters"""
    n = 2 ** mem_cost
    p = 1
    user_salt: bytes = base64.b64decode(salt)
    salt_separator: bytes = base64.b64decode(salt_separator)
    password: bytes = bytes(password, 'utf-8')

    derived_key = hashlib.scrypt(
        password=password,
        salt=user_salt + salt_separator,
        n=n,
        r=rounds,
        p=p,
    )

    return derived_key

def encrypt(signer_key: bytes, derived_key: bytes) -> bytes:
    """Encrypts signer key with derived key using AES256

    NOTE: We're only using first 32 bytes of the derived key to match
    expected key length.
    
    Nonce is fixed and IV-vector is basically 16 null bytes (counter starting from 0).
    
    See: https://pycryptodome.readthedocs.io/en/latest/src/faq.html#is-ctr-cipher-mode-compatible-with-java
    """
    key = derived_key[:32]
    iv = b'\x00' * 16
    nonce=b''
    crypter = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=nonce)

    result = crypter.encrypt(signer_key)

    return result
    

def verify_password(
    password: str,
    known_hash: str,
    salt: str,
    salt_separator: str,
    signer_key: str,
    rounds: int,
    mem_cost: int
) -> bool:
    """Verify if password matches known hash"""
    derived_key: bytes = generate_derived_key(password, salt, salt_separator, rounds, mem_cost)
    signer_key: bytes = base64.b64decode(signer_key)

    result = encrypt(signer_key, derived_key)

    password_hash = base64.b64encode(result).decode('utf-8')

    if password_hash == known_hash:
        return True
    
    raise InvalidPassword()