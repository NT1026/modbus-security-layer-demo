import time

from dotenv import load_dotenv
from scapy.all import *

from modbus import create_modbus_secure_layer_pkt, create_modbus_tcp_layer_pkt
from utils import generate_timestamp, read_modbus_packet

# Load environment variables
load_dotenv(override=True)

HMAC_ALGORITHM_IDENTIFIER = int(os.getenv("HMAC_ALGORITHM_IDENTIFIER"))
MASTER_PRE_SHARE_HMAC_KEY = os.getenv("MASTER_PRE_SHARE_HMAC_KEY").encode()
DESTINATION_IP = os.getenv("DESTINATION_IP")
DESTINATION_PORT = int(os.getenv("DESTINATION_PORT"))


def main():
    # Generate a timestamp in microseconds
    timestamp = generate_timestamp()
    salting_key = b"$" + str(timestamp).encode() + b"$" + MASTER_PRE_SHARE_HMAC_KEY

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
    secure_layer = create_modbus_secure_layer_pkt(
        timestamp=timestamp,
        modbus_tcp_layer_pkt=modbus_tcp_layer,
        hmac_algorithm_id=HMAC_ALGORITHM_IDENTIFIER,
        hmac_key=salting_key,
    )
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
        print(f"Packet sent in {end - start:.4f} seconds")
        print(f"Received packet payload: {res.load}")
        print("---")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
