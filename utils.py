import hashlib
import hmac
import time

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
