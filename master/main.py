import time
from scapy.all import *

from modbus import create_modbus_pkt, create_modbus_sec_pkt
from utils import get_hmac, hashing_info, SLAVE_IP, SLAVE_PORT, HMAC_ALGORITHM_ID


def main():
    modbus_pkt = create_modbus_pkt(
        transaction_identifier=0xAAAA,
        unit_identifier=0xBB,
        function_code=4,
        reference_number=0xCCCC,
        word_count=0xDDDD,
    )

    modbus_sec_pkt = create_modbus_sec_pkt(modbus_pkt)

    # Show final packet
    pkt = Raw(modbus_sec_pkt / modbus_pkt)
    pkt.show()

    # Socket
    try:
        s = socket.socket()
        s.connect((SLAVE_IP, SLAVE_PORT))
        ss = StreamSocket(s, Raw)

        while True:
            try:
                ss.sr1(pkt)
                time.sleep(1)
            except KeyboardInterrupt:
                break

        print(f"\n\nHMAC-{hashing_info[HMAC_ALGORITHM_ID]['algorithm'].__name__[8:]} of the Modbus packet:")
        print(
            get_hmac(
                data=bytes(modbus_pkt),
                hashing_algorithm=hashing_info[HMAC_ALGORITHM_ID]["algorithm"],
            ).hex()
        )

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
