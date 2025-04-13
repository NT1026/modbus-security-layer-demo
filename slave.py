import socket
from dotenv import load_dotenv
from scapy.all import *

from modbus import ModbusSecureLayer, ModbusTCP, Modbus
from utils import get_hmac, hashing_info


def main():
    # Load environment variables
    load_dotenv(override=True)

    SLAVE_PRE_SHARE_HMAC_KEY = os.getenv("SLAVE_PRE_SHARE_HMAC_KEY").encode()
    HOST = os.getenv("HOST")
    PORT = int(os.getenv("PORT"))

    # Bind layers
    bind_layers(ModbusSecureLayer, ModbusTCP)
    bind_layers(ModbusTCP, Modbus)

    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connection from {addr} established.")
            while True:
                print("---")
                data = conn.recv(1024)
                if not data:
                    break
                print("Raw data received:", data.hex())

                try:
                    # Parse modbus secure layer packet
                    modbus_sec_layer = ModbusSecureLayer(data)
                    modbus_sec_layer.show()

                    hmac_algorithm_id = modbus_sec_layer.fields[
                        "HMAC_Algorithm_Identifier"
                    ]
                    received_hmac_hash = modbus_sec_layer.fields["HMAC_Hash"]

                    timestamp = modbus_sec_layer.fields["Timestamp"]
                    salting_key = (
                        b"$" + str(timestamp).encode() + b"$" + SLAVE_PRE_SHARE_HMAC_KEY
                    )

                    # Check if HMAC hash is valid
                    calculated_hmac_hash = get_hmac(
                        hmac_key=salting_key,
                        data=bytes(modbus_sec_layer.payload),
                        hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
                    )

                    print("Received HMAC hash:   ", received_hmac_hash.hex())
                    print("Calculated HMAC hash: ", calculated_hmac_hash.hex())

                    if received_hmac_hash != calculated_hmac_hash:
                        print("Packet is INVALID")
                    else:
                        print("Packet is VALID")

                    # Resend the packet to the master
                    conn.sendall(data)

                except Exception as e:
                    print(f"Parse Failed: {e}")


if __name__ == "__main__":
    main()
