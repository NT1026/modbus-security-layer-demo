from scapy.all import *
from scapy.layers.inet import IP, TCP
import socket

# 自訂封包處理函數
def packet_handler(packet):
    # 檢查是否為 TCP 並且目標端口是 8888
    if packet.haslayer(TCP) and packet[TCP].dport == 8888:
        print(f"Received packet from {packet[IP].src} to {packet[IP].dst} on port 8888")
        # 顯示封包的詳細內容
        packet.show()

# 設定 sniff() 來捕獲封包並處理
def start_sniffing():
    sniff(filter="tcp port 8888", prn=packet_handler, store=0)  # prn 是處理函數，store=0 不儲存封包

# 開始監聽
if __name__ == "__main__":
    print("Listening on port 8888...")
    start_sniffing()