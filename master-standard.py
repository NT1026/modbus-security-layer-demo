import time

from dotenv import load_dotenv
from scapy.all import *

from modbus import create_modbus_secure_layer_pkt, create_modbus_tcp_layer_pkt
from utils import generate_timestamp, read_modbus_packet


def main():
    # Load environment variables
    load_dotenv(override=True)

    DESTINATION_IP = os.getenv("DESTINATION_IP")
    DESTINATION_PORT = int(os.getenv("DESTINATION_PORT"))

    # Read packet.conf
    pkt_dict = read_modbus_packet()

    # Create a standard modbus tcp packet
    modbus_tcp_layer = create_modbus_tcp_layer_pkt(
        transaction_identifier=pkt_dict["Transaction_Identifier"],
        unit_identifier=pkt_dict["Unit_Identifier"],
        function_code=pkt_dict["Function_Code"],
        reference_number=pkt_dict["Reference_Number"],
        word_count=pkt_dict["Word_Count"],
    )
    modbus_tcp_layer.show()

    # Socket
    try:
        s = socket.socket()
        s.connect((DESTINATION_IP, DESTINATION_PORT))
        ss = StreamSocket(s, Raw)

        # Send the packet
        start = time.perf_counter()
        ss.sr1(modbus_tcp_layer, verbose=True)
        end = time.perf_counter()
        print("---")
        print(f"Packet sent in {end - start:.4f} seconds")
        print("---")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
