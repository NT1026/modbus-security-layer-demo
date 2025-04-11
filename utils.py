import hashlib
import hmac
import os
from dotenv import load_dotenv

load_dotenv()

HMAC_ALGORITHM_ID = int(os.getenv("HMAC_ALGORITHM_ID"))
HMAC_KEY = os.getenv("HMAC_KEY").encode()
SLAVE_IP = os.getenv("SLAVE_IP")
SLAVE_PORT = int(os.getenv("SLAVE_PORT"))

hashing_info = {
    0: {"algorithm": hashlib.sha256, "length": 32},
    1: {"algorithm": hashlib.md5, "length": 16},
    2: {"algorithm": hashlib.sha1, "length": 20},
}


# Calculate HMAC
def get_hmac(data, hashing_algorithm):
    return hmac.new(HMAC_KEY, data, hashing_algorithm).digest()
