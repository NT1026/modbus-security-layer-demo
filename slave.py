import socket
from dotenv import load_dotenv
from scapy.all import *

from modbus import ModbusSecureLayer, ModbusTCP, Modbus
from utils import generate_timestamp, get_hmac, hashing_info


def main():
    # Load environment variables
    load_dotenv(override=True)

    SLAVE_PRE_SHARE_HMAC_KEY = os.getenv("SLAVE_PRE_SHARE_HMAC_KEY").encode()
    MIDDLEWARE_IP = os.getenv("MIDDLEWARE_IP")
    MIDDLEWARE_PORT = int(os.getenv("MIDDLEWARE_PORT"))
    SLAVE_IP = os.getenv("SLAVE_IP")
    SLAVE_PORT = int(os.getenv("SLAVE_PORT"))

    # Bind layers
    bind_layers(ModbusSecureLayer, ModbusTCP)
    bind_layers(ModbusTCP, Modbus)

    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((MIDDLEWARE_IP, MIDDLEWARE_PORT))
        s.listen()
        print(f"Listening on {MIDDLEWARE_IP}:{MIDDLEWARE_PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connection from {addr} established.")
            print("---")
            data = conn.recv(1024)
            print("Raw data received:", data.hex())

            try:
                # Parse modbus secure layer packet
                modbus_sec_layer = ModbusSecureLayer(data)
                print("---")
                modbus_sec_layer.show()

                hmac_algorithm_id = modbus_sec_layer.fields["HMAC_Algorithm_Identifier"]
                received_hmac_hash = modbus_sec_layer.fields["HMAC_Hash"]

                # Check if timestamp is valid (in 60 seconds)
                timestamp = modbus_sec_layer.fields["Timestamp"]
                current_time = generate_timestamp()

                print("---")
                if current_time - timestamp <= 60_000_000:
                    print("Timestamp is VALID")
                else:
                    print("Timestamp is INVALID")
                    # Return the same packet to the master
                    conn.sendall(data)

                salting_key = (
                    b"$" + str(timestamp).encode() + b"$" + SLAVE_PRE_SHARE_HMAC_KEY
                )

                # Check if HMAC hash is valid
                calculated_hmac_hash = get_hmac(
                    hmac_key=salting_key,
                    data=bytes(modbus_sec_layer.payload),
                    hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
                )

                print("---")
                print("Received HMAC hash:   ", received_hmac_hash.hex())
                print("Calculated HMAC hash: ", calculated_hmac_hash.hex())

                if received_hmac_hash != calculated_hmac_hash:
                    print("Packet is INVALID")

                    # Return the same packet to the master
                    conn.sendall(data)

                else:
                    print("Packet is VALID")
                    # Resend the Modbus TCP packet to <slave_ip>:502
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
                        s2.connect((SLAVE_IP, SLAVE_PORT))
                        s2.sendall(bytes(modbus_sec_layer.payload))
                        print("---")
                        print(f"Modbus TCP packet resent to {SLAVE_IP}:502")
                        response = s2.recv(1024)

                        # Return response from <slave_ip>:502 to the master
                        conn.sendall(response)

            except Exception as e:
                print(f"Parse Failed: {e}")


if __name__ == "__main__":
    main()
