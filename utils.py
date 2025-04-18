import hashlib
import hmac
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

hashing_info = {
    0: {"algorithm": hashlib.sha256, "length": 32},
    1: {"algorithm": hashlib.md5, "length": 16},
    2: {"algorithm": hashlib.sha1, "length": 20},
}


# Calculate HMAC
def get_hmac(hmac_key, data, hashing_algorithm):
    return hmac.new(hmac_key, data, hashing_algorithm).digest()


# Generate a timestamp in microseconds
def generate_timestamp():
    return int(time.time() * 1_000_000)


# Read standard modbus tcp packet
def read_modbus_packet():
    packet_dict = {}
    with open("packet.conf", "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                packet_dict[key.strip()] = int(value.strip(), 16)

    return packet_dict


# Generate a new key pair and store
def generate_key_pair(role):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(f"{role}_private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(f"{role}_public_key.pem", "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def HKDF_derive_key(private_key, public_key, salt, info, length):
    # Generate the shared secret
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
    )
    public_key = serialization.load_pem_public_key(public_key)
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive the key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)
