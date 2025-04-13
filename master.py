import time
from scapy.all import *

from modbus import create_modbus_sec_layer_pkt, create_modbus_tcp_layer_pkt
from utils import SLAVE_IP, SLAVE_PORT


def main():
    # Create a modbus secure layer packet
    modbus_tcp_layer = create_modbus_tcp_layer_pkt(
        transaction_identifier=0xAAAA,
        unit_identifier=0xBB,
        function_code=4,
        reference_number=0xCCCC,
        word_count=0xDDDD,
    )

    modbus_sec_layer = create_modbus_sec_layer_pkt(modbus_tcp_layer)
    modbus_sec_layer.show()

    # Socket
    try:
        s = socket.socket()
        s.connect((SLAVE_IP, SLAVE_PORT))
        ss = StreamSocket(s, Raw)

        while True:
            try:
                ss.sr1(modbus_sec_layer, verbose=True)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
