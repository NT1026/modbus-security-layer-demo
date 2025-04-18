import time

from dotenv import load_dotenv
from scapy.all import *

from modbus import create_modbus_tcp_layer_pkt
from utils import read_modbus_packet

# Load environment variables
load_dotenv(override=True)

STANDARD_DESTINATION_IP = os.getenv("STANDARD_DESTINATION_IP")
STANDARD_DESTINATION_PORT = int(os.getenv("STANDARD_DESTINATION_PORT"))


def main():
    # Create a standard modbus tcp packet
    pkt_dict = read_modbus_packet()
    modbus_tcp_layer = create_modbus_tcp_layer_pkt(
        transaction_identifier=pkt_dict["Transaction_Identifier"],
        unit_identifier=pkt_dict["Unit_Identifier"],
        function_code=pkt_dict["Function_Code"],
        reference_number=pkt_dict["Reference_Number"],
        word_count=pkt_dict["Word_Count"],
    )
    modbus_tcp_layer.show()

    # Send one standard modbus packet
    try:
        s = socket.socket()
        s.connect((STANDARD_DESTINATION_IP, STANDARD_DESTINATION_PORT))
        ss = StreamSocket(s, Raw)

        start = time.perf_counter()
        res = ss.sr1(modbus_tcp_layer, verbose=True)
        end = time.perf_counter()

        print("---")
        print(f"Packet sent in {end - start:.4f} seconds, received packet payload: {res.load.hex()}")
        print("---")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
