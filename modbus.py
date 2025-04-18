from scapy.all import *

from utils import get_hmac, hashing_info


# ICS Protocol Secure Layer
class ModbusSecureLayer(Packet):
    name = "ModbusSecureLayer"
    fields_desc = [
        XByteField(
            "Encapsulated_Protocol_Identifier", 0
        ),  # 1 byte. Fixed value, for Modbus TCP
        LongField("Timestamp", 0),  # 8 bytes. Timestamp
        XByteField("HMAC_Algorithm_Identifier", 0),  # 1 byte. Hash algorithm identifier
        ShortField("HMAC_Length", 0),  # 2 bytes. Length of the HMAC hash
        StrFixedLenField("HMAC_Hash", 0, 32),  # 32 bytes. HMAC hash
    ]


# Modbus TCP Layer
class ModbusTCP(Packet):
    name = "Modbus/TCP"
    fields_desc = [
        ShortField("Transaction_Identifier", 0),  # 2 bytes. Random value
        ShortField("Protocol_Identifier", 0),  # 2 bytes. Fixed value, for Modbus
        ShortField(
            "Length", 6
        ),  # 2 bytes. Fixed value, length (bytes) of the following fields
        XByteField("Unit_Identifier", 0),  # 1 byte. Slave Address
    ]


# Modbus Layer
class Modbus(Packet):
    name = "Modbus"
    fields_desc = [
        XByteField("Function_Code", 0),  # 1 byte. Read Input Registers
        ShortField("Reference_Number", 0),  # 2 bytes. Starting Address
        ShortField("Word_Count", 0),  # 2 bytes. Number of Registers to Read
    ]


def create_modbus_tcp_layer_pkt(
    transaction_identifier, unit_identifier, function_code, reference_number, word_count
):
    return ModbusTCP(
        Transaction_Identifier=transaction_identifier,  # Custom
        Protocol_Identifier=0,  # Fixed
        Length=6,  # Fixed
        Unit_Identifier=unit_identifier,  # Custom
    ) / Modbus(
        Function_Code=function_code,  # Custom
        Reference_Number=reference_number,  # Custom
        Word_Count=word_count,  # Custom
    )


def create_modbus_secure_layer_pkt(
    timestamp, modbus_tcp_layer_pkt, hmac_algorithm_id, hmac_key
):
    return (
        ModbusSecureLayer(
            Encapsulated_Protocol_Identifier=0,
            Timestamp=timestamp,
            HMAC_Algorithm_Identifier=hmac_algorithm_id,
            HMAC_Length=hashing_info[hmac_algorithm_id]["length"],
            HMAC_Hash=get_hmac(
                hmac_key=bytes(hmac_key),
                data=bytes(modbus_tcp_layer_pkt) + timestamp.to_bytes(8, "big"),
                hashing_algorithm=hashing_info[hmac_algorithm_id]["algorithm"],
            ),
        )
        / modbus_tcp_layer_pkt
    )
