import socket
from scapy.all import *

from modbus import ModbusSec, ModbusTCP, Modbus
from utils import get_hmac, hashing_info

HOST = "0.0.0.0"
PORT = 8888

def main():
    # Bind layers
    bind_layers(ModbusSec, ModbusTCP)
    bind_layers(ModbusTCP, Modbus)

    # Create a socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on port {PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                print("---")
                data = conn.recv(1024)
                if not data:
                    break
                print("Raw data received:", data.hex())

                try:
                    # Parse customized secure layer packet
                    modbus_sec_layer = ModbusSec(data)
                    modbus_tcp_layer = modbus_sec_layer.payload

                    hmac_algorithm_id = modbus_sec_layer.fields["HMAC_Algorithm_Identifier"]
                    received_hmac_hash = modbus_sec_layer.fields["HMAC_Hash"]

                    # Check if HMAC hash is valid
                    calculated_hmac_hash = get_hmac(
                        data=bytes(modbus_tcp_layer),
                        hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
                    )

                    print("Received HMAC hash:   ", received_hmac_hash.hex())
                    print("Calculated HMAC hash: ", calculated_hmac_hash.hex())

                    if received_hmac_hash != calculated_hmac_hash:
                        print("Packet is INVALID")
                        continue
                    else:
                        print("Packet is VALID")

                    # resend the packet
                    conn.sendall(data)

                except Exception as e:
                    print(f"Parse Failed: {e}")


if __name__ == "__main__":
    main()