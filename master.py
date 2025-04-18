import time

from dotenv import load_dotenv
from scapy.all import *

from modbus import create_modbus_secure_layer_pkt, create_modbus_tcp_layer_pkt
from utils import generate_timestamp, read_modbus_packet


def main():
    # Load environment variables
    load_dotenv(override=True)

    HMAC_ALGORITHM_IDENTIFIER = int(os.getenv("HMAC_ALGORITHM_IDENTIFIER"))
    MASTER_PRE_SHARE_HMAC_KEY = os.getenv("MASTER_PRE_SHARE_HMAC_KEY").encode()
    DESTINATION_IP = os.getenv("DESTINATION_IP")
    DESTINATION_PORT = int(os.getenv("DESTINATION_PORT"))

    # Generate a timestamp in microseconds
    timestamp = generate_timestamp()
    salting_key = b"$" + str(timestamp).encode() + b"$" + MASTER_PRE_SHARE_HMAC_KEY
    
    # Read packet.conf
    pkt_dict = read_modbus_packet()

    # Create a modbus secure layer packet
    modbus_tcp_layer = create_modbus_tcp_layer_pkt(
        transaction_identifier=pkt_dict["Transaction_Identifier"],
        unit_identifier=pkt_dict["Unit_Identifier"],
        function_code=pkt_dict["Function_Code"],
        reference_number=pkt_dict["Reference_Number"],
        word_count=pkt_dict["Word_Count"],
    )

    secure_layer = create_modbus_secure_layer_pkt(
        timestamp=timestamp,
        modbus_tcp_layer_pkt=modbus_tcp_layer,
        hmac_algorithm_id=HMAC_ALGORITHM_IDENTIFIER,
        hmac_key=salting_key,
    )
    secure_layer.show()

    # Socket
    try:
        s = socket.socket()
        s.connect((DESTINATION_IP, DESTINATION_PORT))
        ss = StreamSocket(s, Raw)

        # Send the packet
        start = time.perf_counter()
        ss.sr1(secure_layer, verbose=True)
        end = time.perf_counter()
        print("---")
        print(f"Salting key: {salting_key.decode()}")
        print("---")
        print(f"Packet sent in {end - start:.4f} seconds")
        print("---")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
