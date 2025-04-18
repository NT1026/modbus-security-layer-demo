import time

from dotenv import load_dotenv
from scapy.all import *

from modbus import create_modbus_secure_layer_pkt, create_modbus_tcp_layer_pkt
from utils import HKDF_derive_key, generate_timestamp, read_modbus_packet

# Load environment variables
load_dotenv(override=True)

MASTER_HMAC_KEY_TYPE = os.getenv("MASTER_HMAC_KEY_TYPE")
MASTER_HKDF_SALT = os.getenv("MASTER_HKDF_SALT").encode()
MASTER_HKDF_INFO = os.getenv("MASTER_HKDF_INFO").encode()

HMAC_ALGORITHM_IDENTIFIER = int(os.getenv("HMAC_ALGORITHM_IDENTIFIER"))
MASTER_PRE_SHARE_HMAC_KEY = os.getenv("MASTER_PRE_SHARE_HMAC_KEY").encode()
DESTINATION_IP = os.getenv("DESTINATION_IP")
DESTINATION_PORT = int(os.getenv("DESTINATION_PORT"))


def read_ECDH_keys():
    # Read the ECDH keys from the files
    try:
        with open("demo-keys/master_private_key.pem", "rb") as f:
            master_private_key = f.read()

        with open("demo-keys/middleware_public_key.pem", "rb") as f:
            middleware_public_key = f.read()

        return master_private_key, middleware_public_key

    except:
        print("Error: ECDH keys not found.")
        exit(1)


def main():
    # Generate a timestamp in microseconds
    timestamp = generate_timestamp()

    # Create a standard modbus tcp packet
    pkt_dict = read_modbus_packet()
    modbus_tcp_layer = create_modbus_tcp_layer_pkt(
        transaction_identifier=pkt_dict["Transaction_Identifier"],
        unit_identifier=pkt_dict["Unit_Identifier"],
        function_code=pkt_dict["Function_Code"],
        reference_number=pkt_dict["Reference_Number"],
        word_count=pkt_dict["Word_Count"],
    )

    # Create a modbus secure layer packet
    print("---")
    if MASTER_HMAC_KEY_TYPE == "preshared":
        secure_layer = create_modbus_secure_layer_pkt(
            timestamp=timestamp,
            modbus_tcp_layer_pkt=modbus_tcp_layer,
            hmac_algorithm_id=HMAC_ALGORITHM_IDENTIFIER,
            hmac_key=MASTER_PRE_SHARE_HMAC_KEY,
        )
        print("Using pre-shared key for HMAC.")
        print(f"Pre-shared key: {MASTER_PRE_SHARE_HMAC_KEY.hex()}")

    elif MASTER_HMAC_KEY_TYPE == "ECDH":
        # Read the ECDH keys and use HDKF to derive the shared secret
        master_private_key, middleware_public_key = read_ECDH_keys()
        shared_secret_key = HKDF_derive_key(
            private_key=master_private_key,
            public_key=middleware_public_key,
            salt=MASTER_HKDF_SALT,
            info=MASTER_HKDF_INFO,
            length=32,
        )
        secure_layer = create_modbus_secure_layer_pkt(
            timestamp=timestamp,
            modbus_tcp_layer_pkt=modbus_tcp_layer,
            hmac_algorithm_id=HMAC_ALGORITHM_IDENTIFIER,
            hmac_key=shared_secret_key,
        )
        print("Using ECDH-derived key for HMAC.")
        print(f"ECDH-derived key: {shared_secret_key.hex()}")

    print("---")
    secure_layer.show()

    # Send one customized modbus packet
    try:
        s = socket.socket()
        s.connect((DESTINATION_IP, DESTINATION_PORT))
        ss = StreamSocket(s, Raw)

        start = time.perf_counter()
        res = ss.sr1(secure_layer, verbose=True)
        end = time.perf_counter()

        print("---")
        print(
            f"Packet sent in {end - start:.4f} seconds, received packet payload: {res.load.hex()}"
        )
        print("---")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
