from scapy.all import *

from utils import get_hmac, hashing_info, HMAC_ALGORITHM_ID


# ICS Protocol Secure Layer
class ModbusSec(Packet):
    name = "ModbusSec"
    fields_desc = [
        XByteField("Encapsulated_Protocol_Identifier", 0),  # Fixed value, for Modbus
        XByteField("HMAC_Algorithm_Identifier", 0),  # Hashing algorithm identifier
        ShortField("HMAC_Length", 0),  # Length of the HMAC hash
        StrFixedLenField("HMAC_Hash", b"\x00" * 32, 32),
    ]


# Modbus ADU
class ModbusTCP(Packet):
    name = "Modbus/TCP"
    fields_desc = [
        ShortField("Transaction_Identifier", 0),  # Random value
        ShortField("Protocol_Identifier", 0),  # Fixed value, for Modbus
        ShortField("Length", 6),  # Fixed value, length (bytes) of the following fields
        XByteField("Unit_Identifier", 0),  # Slave Address
    ]


# Modbus PDU
class Modbus(Packet):
    name = "Modbus"
    fields_desc = [
        XByteField("Function_Code", 0),  # Read Input Registers
        ShortField("Reference_Number", 0),  # Starting Address
        ShortField("Word_Count", 0),  # Number of Registers to Read
    ]


def create_modbus_tcp_layer_pkt(
    transaction_identifier, unit_identifier, function_code, reference_number, word_count
):
    return ModbusTCP(
        Transaction_Identifier=transaction_identifier,  # Random value
        Protocol_Identifier=0,  # Fixed
        Length=6,  # Fixed
        Unit_Identifier=unit_identifier,  # Slave Address
    ) / Modbus(
        Function_Code=function_code,
        Reference_Number=reference_number,
        Word_Count=word_count,
    )


def create_modbus_sec_layer_pkt(modbus_tcp_layer_pkt):
    return ModbusSec(
        Encapsulated_Protocol_Identifier=0,
        HMAC_Algorithm_Identifier=HMAC_ALGORITHM_ID,
        HMAC_Length=hashing_info[HMAC_ALGORITHM_ID]["length"],
        HMAC_Hash=get_hmac(
            data=bytes(modbus_tcp_layer_pkt),
            hashing_algorithm=hashing_info[HMAC_ALGORITHM_ID]["algorithm"],
        ),
    ) / modbus_tcp_layer_pkt
