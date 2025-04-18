# Modbus Secure Layer Demo

## Description

- Use `Scapy` to customeze packet
- `PACKET = ModbusSecure() / ModbusTCP() / Modbus()`
- Master send customized Modbus packet to middleware
- Middleware parse customized Mobdus packet
    - Checking data integrity
    - Authertication
    - Resending Modbus TCP packet to slave


## Usage

- Config in `.env`
- Edit the standard Modbus TCP packet
- Send standard Modbus TCP packet: `python3 master_standard.py`
- Send customized Modbus packet: `python3 master.py`
- Middleware parses customized packet and resend to slave: `python3 middleware.py`
- Slave simulator: `python3 plc_simulator.py`


## Test

- Send packet multiple times: `./test.sh [-v] [-n <num>] master.py | master-standard.py`
    - `-v`: verbose 
    - `-n <number>`: how many packet to send

- Example: 
    - `./test.sh master.py`
    - `./test.sh -v master-standard.py`
    - `./test.sh -v -n 10000 master.py`


## Reference

- https://ieeexplore.ieee.org/document/6579545
