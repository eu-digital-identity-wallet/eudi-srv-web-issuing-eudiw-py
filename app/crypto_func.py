# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend. 
Its main goal is to issue the PID in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This crypto_func.py file includes the needed crypto functions.
"""
import base64
from tinyec import (registry, ec)
import hashlib, secrets
from Crypto.Cipher import AES
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec as ec2
from cryptography.hazmat.primitives import serialization


def pubkeyDER(x, y, curve=ec2.SECP256R1()):
    """Returns public key in DER format, using the x, y coordinates and the curve
    
    Keyword arguments:
    + x -- public key x coordinate
    + y -- public key y coordinate
    + curve -- Elliptic Cryptography curve

    Return: Public key in DER format
    """
    # Create the public key using the x, y coordinates and the curve
    public_key = ec2.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
    # Serialize the public key in DER format
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes



def pubkeyPoint(pubkey):
    """Transforms DER Public key (pubkey) into Point type
    
    Keyword arguments:
    + pubkey - public key (DER format)

    Return: Public key in Point type
    """
    return ec.Point(registry.get_curve(pubkey.public_numbers().curve.name), 
                    pubkey.public_numbers().x, 
                    pubkey.public_numbers().y)



###
# ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM
#
# For more information on ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM please 
# read https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption.
#
###

def eccEnc(certificate, msg:str, curve = 'secp256r1'):
    """ECC-Based Hybrid Encryption (using ECDH) + AES-256-GCM. Ciphers msg with detived symetric key from certificate. 
    The validation of the certificate (algorithm, curve, ...) must be performed outside this function.
    
    Keyword arguments:
    + certificate -- certificate im PEM format
    + msg -- message to be encrypted 
    + curve -- public key curve

    Return: (ciphertext, nonce, authTag, ciphertextPubKey), where the values:
    + ciphertext - msg ciphered (AES-256-GCM) with a symetric key derived from the certificate public key
    + nonce - random AES initialization vector
    + authTag - MAC code of the encrypted text, obtained by the GCM block mode
    + ciphertextPubKey - randomly generated ephemeral public key, that will be used by the ciphertext receiver to derive the symmetric encryption key, using the ECDH key agreement scheme
    """
    c = registry.get_curve(curve)
    pubKey = get_public_point_from_certificate(certificate, c)

    return encrypt_ECC(msg.encode("utf-8"), pubKey, c)
 

def decrypt_ECC(ciphertext, nonce, authTag, ciphertextPubKey, privKey):
    """Decipher ciphertext and returns the plaintext 
    
    Keyword arguments:
    + ciphertext - ciphered text (AES-256-GCM)
    + nonce - random AES initialization vector
    + authTag - MAC code of the encrypted text, obtained by the GCM block mode
    + ciphertextPubKey - randomly generated ephemeral public key (Point type), that will be used by the ciphertext receiver to derive the symmetric encryption key, using the ECDH key agreement scheme.
    + privKey - private key (private value) to derive the symmetric encryption key

    Return: plaintext - ciphertext deciphered
    """
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext


def get_public_point_from_certificate(certificate, curve):
    """Return public key point
    
    Keyword arguments:
    + certificate -- certificate im PEM format
    + curve -- public key curve (type Curve)

    Return: public key point (type Point)
    """
    cert = x509.load_pem_x509_certificate(certificate, default_backend())
    ec_public_numbers = cert.public_key().public_numbers()

    # return Point object
    return ec.Point(curve, ec_public_numbers.x, ec_public_numbers.y)


def encrypt_ECC(msg, pubKey, curve):
    """Encrypt msg with shared key derived from the public key point (pubKey) 
    
    Keyword arguments:
    + msg -- message to be encrypted (binary/encoded)
    + pubKey -- public key point (type Point)
    + curve -- public key curve (type Curve)

    Return: (ciphertext, nonce, authTag, ciphertextPubKey), where
    + ciphertext - msg ciphered (AES-256-GCM) with a symetric key derived from the pubKey
    + nonce - random AES initialization vector
    + authTag - the MAC code of the encrypted text, obtained by the GCM block mode
    + ciphertextPubKey - randomly generated ephemeral public key, that will be used by the ciphertext receiver to derive the symmetric encryption key, using the ECDH key agreement scheme
    """
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)


def encrypt_AES_GCM(msg, secretKey):
    """Encrypt (AES-GCM) msg with secretKey
    
    Keyword arguments:
    + msg -- message to be encrypted (binary/encoded)
    + secretKey -- secret key. It must be 16 (*AES-128)*, 24 (*AES-192*) or 32 (*AES-256*) bytes long.

    Return: (ciphertext, nonce, authTag, ciphertextPubKey), where
    + ciphertext - msg ciphered (AES-128-GCM/AES-192-GCM/AES-256-GCM depending on the number of bytes 16/24/32 of the secretKey) with secretKey.
    + nonce - random AES initialization vector
    + authTag - the MAC code of the encrypted text, obtained by the GCM block mode
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def ecc_point_to_256_bit_key(point):
    """Derive 32 bytes (256 bit) secret key from point"""
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()



def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    """Decrypt (AES-GCM) msg with secretKey
    
    Keyword arguments:
    + ciphertext - msg ciphered (AES-128-GCM/AES-192-GCM/AES-256-GCM depending on the number of bytes 16/24/32 of the secretKey) with secretKey.
    + nonce - random AES initialization vector
    + authTag - the MAC code of the encrypted text, obtained by the GCM block mode
    + secretKey -- secret key. It must be 16 (*AES-128)*, 24 (*AES-192*) or 32 (*AES-256*) bytes long.

    Return: plaintext - ciphertext deciphered
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext



