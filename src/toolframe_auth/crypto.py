"""Salted scrypt verification and separately keyed secret identification."""

import hashlib
import hmac
import secrets

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def lookup(key, secret):
    return hmac.new(key, secret.encode(), hashlib.sha256).hexdigest()


def verifier(secret, salt):
    return hashlib.scrypt(
        secret.encode(),
        salt=bytes.fromhex(salt),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=256 * 1024 * 1024,
        dklen=32,
    ).hex()


def new_verifier(secret):
    salt = secrets.token_hex(16)
    return salt, verifier(secret, salt)


def session_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()
