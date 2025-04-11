# Modbus Secure Layer Demo

## Description

- Use `Scapy` to customeze packet.
- `PACKET = ModbusSecure() / ModbusTCP() / Modbus()`
- Master send customized Modbus packet to slave.
- Slave parse customized Mobdus packet
    - Checking data integrity
    - Authertication
    - Resending Modbus TCP packet to 502 port


## Usage

- Config in `.env`
- Send customized packet: `python3 master.py`
- Parse customized packet and resend to 502 port: `python3 slave.py`


## Reference

- https://ieeexplore.ieee.org/document/6579545
