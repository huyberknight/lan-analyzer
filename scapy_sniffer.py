# scapy_sniffer.py
from scapy.all import sniff, ARP, IP, ICMP, TCP, UDP, Raw, Ether, IPv6
import datetime as dt
import binascii

# ==============================
# PARSE 1 PACKET
# ==============================


def parse_packet(pkt):

    timestamp = dt.datetime.now()

    # ===== GIÁ TRỊ MẶC ĐỊNH =====
    src_ip = "Unknown"
    dst_ip = "Unknown"
    src_mac = "Unknown"
    dst_mac = "Unknown"
    ip_version = "Other"
    transport = "Other"
    application = "Other"
    src_port = 0
    dst_port = 0
    length = len(pkt)
    payload_hex = ""

    try:
        # ===== Ethernet =====
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        # ===== ARP =====
        if pkt.haslayer(ARP):
            ip_version = "ARP"
            transport = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            application = "ARP Request/Reply"

        # ===== IPv4 =====
        elif pkt.haslayer(IP):
            ip_version = "IPv4"
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if pkt.haslayer(ICMP):
                transport = "ICMP"
                application = "Ping"
            elif pkt.haslayer(TCP):
                transport = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                transport = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

        # ===== IPv6 =====
        elif pkt.haslayer(IPv6):
            ip_version = "IPv6"
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

            if pkt.haslayer(TCP):
                transport = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                transport = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

        # ===== APPLICATION DETECT =====
        if dst_port > 0 and application == "Other":
            port_map = {
                80: "HTTP",
                8080: "HTTP",
                8000: "HTTP",
                8888: "HTTP",
                443: "HTTPS",
                8443: "HTTPS",
                53: "DNS",
                445: "SMB",
                139: "SMB",
                22: "SSH",
                23: "Telnet",
                3389: "RDP",
                20: "FTP",
                21: "FTP",
                25: "SMTP",
                110: "POP3",
                143: "IMAP",
                67: "DHCP",
                68: "DHCP",
                123: "NTP",
            }
            application = port_map.get(dst_port, f"Unknown App (Port {dst_port})")

        # ===== Payload =====
        if pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw])[:256]  # 256 BYTES
            payload_hex = binascii.hexlify(raw_bytes).decode("utf-8")

    except Exception:
        pass

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "ip_version": ip_version,
        "transport": transport,
        "application": application,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "payload": payload_hex,
    }


# ==============================
# SNIFF WRAPPER
# ==============================


def sniff_packets(iface, packet_limit, timeout, on_packet):

    sniff(
        iface=iface if iface and iface.strip() != "" else None,
        prn=on_packet,
        store=False,
        count=packet_limit,
        timeout=timeout,
    )
