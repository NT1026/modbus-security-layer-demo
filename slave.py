import socket
from scapy.all import *

from modbus import ModbusSec, ModbusTCP, Modbus
from utils import hashing_info

HOST = "0.0.0.0"
PORT = 8888

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on port {PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print("Raw data received:", data.hex())

            try:
                pkt = Raw(data).load
                modbus_sec_pkt = ModbusSec(pkt)
                print("ModbusSec:", modbus_sec_pkt.show(dump=True))

                inner_modbus_pkt = ModbusTCP(pkt[len(modbus_sec_pkt) :])
                print("ModbusTCP:", inner_modbus_pkt.show(dump=True))

                pdu = Modbus(pkt[len(modbus_sec_pkt) + len(inner_modbus_pkt) :])
                print("Modbus:", pdu.show(dump=True))

                # Check if the HMAC is valid
                hmac_algorithm = hashing_info[modbus_sec_pkt.HMAC_Algorithm_Identifier][
                    "algorithm"
                ]
                hmac_length = hashing_info[modbus_sec_pkt.HMAC_Algorithm_Identifier][
                    "length"
                ]
                hmac_hash = modbus_sec_pkt.HMAC_Hash[:hmac_length]
                calculated_hmac = hmac_algorithm(bytes(inner_modbus_pkt)).digest()[
                    :hmac_length
                ]
                if hmac_hash == calculated_hmac:
                    print("HMAC is valid")
                else:
                    print("HMAC is invalid")

                # resend the packet
                conn.sendall(data)

            except Exception as e:
                print(f"Parse Failed: {e}")
