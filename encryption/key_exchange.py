__author__ = "moran reisfeld"

import os
import base64

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

#Diffie Hellman

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


def dh_parameters():
    p = int(P_HEX, 16)
    g = 2
    pn = dh.DHParameterNumbers(p, g)
    return pn.parameters()


def dh_server_generate():
    parameters = dh_parameters()
    private_key = parameters.generate_private_key()
    public_key  = private_key.public_key()

    params_pem = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (
        private_key,
        base64.b64encode(params_pem).decode(),
        base64.b64encode(pub_pem).decode(),
    )


def dh_client_generate(params_pem_b64):
    params_pem  = base64.b64decode(params_pem_b64)
    parameters  = serialization.load_pem_parameters(params_pem, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key  = private_key.public_key()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, base64.b64encode(pub_pem).decode()


def dh_derive_aes_key(my_private_key, other_public_pem_b64):
    other_pub_pem = base64.b64decode(other_public_pem_b64)
    other_public  = serialization.load_pem_public_key(other_pub_pem, backend=default_backend())

    shared_secret = my_private_key.exchange(other_public)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    return aes_key