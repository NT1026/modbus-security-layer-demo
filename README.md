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
- Slave simulator: `python3 plc_simulator.py`
- Send standard Modbus TCP packet to slave: `python3 master_standard.py`
- Send customized Modbus packet to middleware: `python3 master.py`
- Middleware parses customized packet and resend to slave: `python3 middleware.py`
- If use ECDH for HKDF key generating, you should do `python3 generate_key_pair.py` first.
    - Master need `demo-keys/master_private_key.pem`, `demo-keys/master_public_key.pem`, and `demo-keys/middleware_public_key.pem`
    - Middleware need `demo-keys/middleware_private_key.pem`, `demo-keys/middleware_public_key.pem`, and `demo-keys/master_public_key.pem`


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
