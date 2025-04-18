import socket
import threading

from dotenv import load_dotenv
from scapy.all import *

from modbus import ModbusSecureLayer, ModbusTCP, Modbus
from utils import HKDF_derive_key, generate_timestamp, get_hmac, hashing_info

# Load environment variables
load_dotenv(override=True)

MIDDLEWARE_HMAC_KEY_TYPE = os.getenv("MIDDLEWARE_HMAC_KEY_TYPE")
MIDDLEWARE_HKDF_SALT = os.getenv("MIDDLEWARE_HKDF_SALT").encode()
MIDDLEWARE_HKDF_INFO = os.getenv("MIDDLEWARE_HKDF_INFO").encode()

SLAVE_PRE_SHARE_HMAC_KEY = os.getenv("SLAVE_PRE_SHARE_HMAC_KEY").encode()
MIDDLEWARE_IP = os.getenv("MIDDLEWARE_IP")
MIDDLEWARE_PORT = int(os.getenv("MIDDLEWARE_PORT"))
SLAVE_IP = os.getenv("SLAVE_IP")
SLAVE_PORT = int(os.getenv("SLAVE_PORT"))

# Bind layers
bind_layers(ModbusSecureLayer, ModbusTCP)
bind_layers(ModbusTCP, Modbus)


def read_ECDH_keys():
    # Read the ECDH keys from the files
    try:
        with open("demo-keys/middleware_private_key.pem", "rb") as f:
            middleware_private_key = f.read()

        with open("demo-keys/master_public_key.pem", "rb") as f:
            master_public_key = f.read()

        return middleware_private_key, master_public_key

    except:
        print("Error: ECDH keys not found.")
        exit(1)


def handle_client(conn, addr):
    with conn:
        print(f"Connection from {addr} established.")
        print("---")
        data = conn.recv(1024)
        print("Raw data received:", data.hex())

        # Parse modbus secure layer packet
        modbus_sec_layer = ModbusSecureLayer(data)

        hmac_algorithm_id = modbus_sec_layer.fields["HMAC_Algorithm_Identifier"]
        received_hmac_hash = modbus_sec_layer.fields["HMAC_Hash"]
        timestamp = modbus_sec_layer.fields["Timestamp"]

        print("---")
        modbus_sec_layer.show()

        # Check if timestamp is valid (in 60 seconds)
        current_time = generate_timestamp()

        print("---")
        if current_time - timestamp <= 60_000_000:
            print("Timestamp is VALID")
        else:
            print("Timestamp is INVALID")
            conn.sendall(data)

        # Check if HMAC hash is valid
        print("---")
        if MIDDLEWARE_HMAC_KEY_TYPE == "preshared":
            calculated_hmac_hash = get_hmac(
                hmac_key=SLAVE_PRE_SHARE_HMAC_KEY,
                data=bytes(modbus_sec_layer.payload) + timestamp.to_bytes(8, "big"),
                hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
            )
            print("Using pre-shared key for HMAC.")
            print(f"Pre-shared key: {SLAVE_PRE_SHARE_HMAC_KEY.hex()}")

        elif MIDDLEWARE_HMAC_KEY_TYPE == "ECDH":
            # Read the ECDH keys and use HDKF to derive the shared secret
            middleware_private_key, master_public_key = read_ECDH_keys()
            shared_secret_key = HKDF_derive_key(
                private_key=middleware_private_key,
                public_key=master_public_key,
                salt=MIDDLEWARE_HKDF_SALT,
                info=MIDDLEWARE_HKDF_INFO,
                length=32,
            )
            calculated_hmac_hash = get_hmac(
                hmac_key=shared_secret_key,
                data=bytes(modbus_sec_layer.payload) + timestamp.to_bytes(8, "big"),
                hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
            )
            print("Using ECDH-derived key for HMAC.")
            print(f"ECDH-derived key: {shared_secret_key.hex()}")

        print("---")
        print("Received HMAC hash:   ", received_hmac_hash.hex())
        print("Calculated HMAC hash: ", calculated_hmac_hash.hex())

        if received_hmac_hash != calculated_hmac_hash:
            print("Packet is INVALID")
            conn.sendall(data)

        else:
            print("Packet is VALID")

            # Resend the Modbus TCP packet to <slave_ip>:502
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                s2.connect((SLAVE_IP, SLAVE_PORT))
                s2.sendall(bytes(modbus_sec_layer.payload))
                print("---")
                print(f"Modbus TCP packet resent to {SLAVE_IP}:502")
                res = s2.recv(1024)

                # Return response from <slave_ip>:502 to the master
                conn.sendall(res)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((MIDDLEWARE_IP, MIDDLEWARE_PORT))
        s.listen()
        print(f"Listening on {MIDDLEWARE_IP}:{MIDDLEWARE_PORT}...")

        while True:
            try:
                conn, addr = s.accept()
                threading.Thread(
                    target=handle_client, args=(conn, addr), daemon=True
                ).start()

            except KeyboardInterrupt:
                print("\n---")
                print("Server shutting down...")
                print("---")
                break

            except Exception as e:
                print("\n---")
                print(f"Error: {e}")
                print("---")
                continue


if __name__ == "__main__":
    main()
