# Modbus Secure Layer Demo

## Description

- Use `Scapy` to customeze packet.
- `PACKET = ModbusSecure() / ModbusTCP() / Modbus()`
- Master send customized Modbus packet to slave.
- Slave parse customized Mobdus packet
    - Checking data integrity
    - Authertication
    - Resending Modbus TCP packet to 502 port


## Reference

- https://ieeexplore.ieee.org/document/6579545
