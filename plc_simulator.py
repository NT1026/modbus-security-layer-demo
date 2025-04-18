import socket
import threading

from dotenv import load_dotenv
from scapy.all import *

from modbus import ModbusSecureLayer, ModbusTCP, Modbus

# Load environment variables
load_dotenv(override=True)

MIDDLEWARE_IP = os.getenv("MIDDLEWARE_IP")
MIDDLEWARE_PORT = int(os.getenv("MIDDLEWARE_PORT"))
SLAVE_IP = os.getenv("SLAVE_IP")
SLAVE_PORT = int(os.getenv("SLAVE_PORT"))

# Bind layers
bind_layers(ModbusSecureLayer, ModbusTCP)
bind_layers(ModbusTCP, Modbus)


def handle_client(conn, addr):
    with conn:
        print(f"Connection from {addr} established.")
        print("---")
        data = conn.recv(1024)
        print("Raw data received:", data.hex())
        conn.sendall(data)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((SLAVE_IP, SLAVE_PORT))
        s.listen()
        print(f"Listening on {SLAVE_IP}:{SLAVE_PORT}...")

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
