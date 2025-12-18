from scapy.all import *
import time
import random

# Cấu hình IP đích (Là IP của máy đang chạy App Streamlit hoặc IP Broadcast)
TARGET_IP = "192.168.56.1"  # <--- ĐỔI IP NÀY THÀNH IP MÁY BẠN (ipconfig/ifconfig)
IFACE = "enp0s3" # <--- Đổi tên card mạng nếu cần

while True:
    try:
        # 1. Giả lập HTTP (Truy cập Web - Port 80)
        # Gửi gói SYN
        pkt_http = IP(dst=TARGET_IP)/TCP(dport=80, sport=random.randint(1024,65535), flags="S")
        send(pkt_http, verbose=0)
        
        # 2. Giả lập DNS Query (Port 53)
        pkt_dns = IP(dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        send(pkt_dns, verbose=0)

        # 3. Giả lập HTTPS (Port 443)
        pkt_https = IP(dst=TARGET_IP)/TCP(dport=443, flags="PA", options=[('MSS', 1460)]) / Raw(load="EncryptedDataSimulator")
        send(pkt_https, verbose=0)

        # 4. Giả lập SSH (Port 22)
        pkt_ssh = IP(dst=TARGET_IP)/TCP(dport=22, flags="S")
        send(pkt_ssh, verbose=0)

        # 5. Giả lập ARP (Hỏi MAC Address)
        pkt_arp = ARP(pdst=TARGET_IP)
        send(pkt_arp, verbose=0)

        # 6. Giả lập Ping (ICMP)
        pkt_icmp = IP(dst=TARGET_IP)/ICMP()
        send(pkt_icmp, verbose=0)

        print(".", end="", flush=True) # In dấu chấm để biết đang chạy
        time.sleep(0.1) # Chỉnh tốc độ bắn (càng nhỏ càng nhanh)

    except KeyboardInterrupt:
        print("\n🛑 Đã dừng.")
        break
    except Exception as e:
        print(f"Lỗi: {e}")
