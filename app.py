from scapy.all import sniff, ARP, IP, ICMP, TCP, UDP, Raw, conf
import streamlit as st
import pandas as pd
import numpy as np
import datetime as dt
import plotly.express as px
import plotly.graph_objects as go
import binascii
import clickhouse_connect

# ==============================
# 1. CẤU HÌNH & GIAO DIỆN
# ==============================
st.set_page_config(
    page_title="LAN Traffic Deep Analyzer",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
    div[data-testid="stMetric"] {
        border: 1px solid #333;
        padding: 15px;
        border-radius: 8px;
        color: #eee;
    }
    .hex-view {
        font-family: 'Consolas', monospace;
        background-color: #0d1117;
        color: #7ee787;
        padding: 15px;
        border-radius: 6px;
        border: 1px solid #30363d;
        font-size: 13px;
        line-height: 1.5;
        overflow-x: auto;
    }
    .header-style {
        font-size: 18px;
        font-weight: bold;
        color: #58a6ff;
        margin-bottom: 10px;
    }
</style>
""",
    unsafe_allow_html=True,
)

# ==============================
# 1.1 KẾT NỐI DATABASE (FIXED)
# ==============================
try:
    ch_client = clickhouse_connect.get_client(
        host="localhost", port=8123, username="default", password="", database="default"
    )

    ch_client.command(
        """
        CREATE TABLE IF NOT EXISTS lan_packets (
            timestamp DateTime64(3),
            src_ip String,
            dst_ip String,
            transport String,
            application String,
            dst_port UInt16,
            length UInt32,
            payload String
        ) ENGINE = MergeTree()
        ORDER BY timestamp
    """
    )

except Exception as e:
    st.error(f"❌ Không thể kết nối ClickHouse: {e}")
    st.stop()


# ==============================
# 2. XỬ LÝ DỮ LIỆU SCAPY
# ==============================
def generate_lan_traffic_from_scapy(iface=None, packet_limit=100, timeout=10):
    # Thanh tiến trình
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Biến đếm cục bộ để update progress bar
    packet_count_local = [0]

    def process_packet(pkt):
        timestamp = dt.datetime.now()

        # Giá trị mặc định
        src_ip = "Unknown"
        dst_ip = "Unknown"
        transport = "Other"
        application = "Other"
        dst_port = 0
        length = len(pkt)
        payload_hex = ""

        try:
            # ===== ARP =====
            if pkt.haslayer(ARP):
                transport = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                length = 64
                application = "ARP Request/Reply"

            # ===== IP BASE =====
            elif pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # ICMP
                if pkt.haslayer(ICMP):
                    transport = "ICMP"
                    application = "Ping"

                # TCP
                elif pkt.haslayer(TCP):
                    transport = "TCP"
                    dst_port = pkt[TCP].dport

                # UDP
                elif pkt.haslayer(UDP):
                    transport = "UDP"
                    dst_port = pkt[UDP].dport

                # ===== LOGIC Application detect =====
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
                    application = port_map.get(
                        dst_port, f"Unknown App (Port {dst_port})"
                    )

            # ===== Payload =====
            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw])[
                    :256
                ]  # Lấy tối đa 256 byte để tránh nặng DB
                payload_hex = binascii.hexlify(raw_bytes).decode("utf-8")

            # ===== INSERT CLICKHOUSE =====
            # Lưu ý: Insert từng dòng (row-by-row) có thể chậm với traffic lớn,
            # nhưng phù hợp với demo realtime.
            ch_client.insert(
                "lan_packets",
                [
                    [
                        timestamp,
                        src_ip,
                        dst_ip,
                        transport,
                        application,
                        dst_port,
                        length,
                        payload_hex,
                    ]
                ],
            )

            # Update progress
            packet_count_local[0] += 1
            if packet_count_local[0] % 2 == 0:  # Update mỗi 2 gói tin để đỡ lag UI
                prog = min(packet_count_local[0] / packet_limit, 1.0)
                progress_bar.progress(prog)
                status_text.text(
                    f"Đang bắt gói tin: {packet_count_local[0]}/{packet_limit}"
                )

        except Exception as e:
            pass

    try:
        actual_iface = iface if iface and iface.strip() != "" else None

        # Bắt đầu Sniff
        sniff(
            iface=actual_iface,
            prn=process_packet,
            store=False,
            count=packet_limit,
            timeout=timeout,
        )
        progress_bar.progress(1.0)
        status_text.text("Hoàn tất!")

    except PermissionError:
        st.error(
            "❌ LỖI QUYỀN: Bạn cần chạy ứng dụng này với quyền Administrator/Root."
        )
    except Exception as e:
        st.error(f"❌ Lỗi Scapy: {e}")

    return True  # Trả về True khi xong


df = ch_client.query_df(
    """
                    SELECT *
                    FROM lan_packets
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """
)

# ==============================
# 3. SIDEBAR ĐIỀU HƯỚNG
# ==============================
with st.sidebar:
    if "traffic_data" not in st.session_state:
        df = ch_client.query_df(
            """
            SELECT *
            FROM lan_packets
            ORDER BY timestamp DESC
            LIMIT 1000
        """
        )
        if not df.empty:
            st.session_state["traffic_data"] = df

    st.title("🕸️ LAN Analyzer")
    st.caption("Scapy Real-time Sniffer")
    st.markdown("---")

    st.subheader("⚙️ Cấu hình Bắt gói tin")

    target_iface = st.text_input("Interface (VD: eth0, Wi-Fi)", value="")
    packet_count = st.slider("Số lượng gói tối đa", 10, 500, 50)
    capture_time = st.slider("Thời gian timeout (giây)", 5, 60, 10)

    if st.button("🚀 Bắt đầu Scan", type="primary"):
        with st.spinner("Đang khởi tạo Scapy và bắt gói tin..."):
            # [FIX] Bỏ comment dòng này để thực sự bắt gói tin
            generate_lan_traffic_from_scapy(
                iface=target_iface, packet_limit=packet_count, timeout=capture_time
            )

            # Sau khi bắt xong, query lại từ DB để hiển thị
            df = ch_client.query_df(
                """
                    SELECT *
                    FROM lan_packets
                    ORDER BY timestamp DESC
                    LIMIT 1000
                """
            )
            st.session_state["traffic_data"] = df
            st.success(f"Đã cập nhật dữ liệu! Tổng số dòng trong view: {len(df)}")

    st.markdown("---")

    menu = st.radio(
        "Chế độ phân tích:",
        [
            "📊 Dashboard Tổng quan",
            "🔀 Phân tích Luồng (Flows)",
            "📦 Phân tích Gói tin (Stats)",
            "🔍 Soi gói tin (Inspector)",
        ],
    )

    if (
        "traffic_data" in st.session_state
        and not st.session_state["traffic_data"].empty
    ):
        df = st.session_state["traffic_data"]

        st.markdown("---")
        st.caption("Bộ lọc hiển thị:")

        # Sửa lỗi: Check nếu cột application tồn tại
        if "application" in df.columns:
            unique_apps = df["application"].unique()
            selected_apps = st.multiselect(
                "Giao thức L7",
                unique_apps,
                default=unique_apps,
            )
            filtered_df = df[df["application"].isin(selected_apps)]
        else:
            filtered_df = df
    else:
        df = pd.DataFrame()
        filtered_df = pd.DataFrame()
        st.info("👈 Bấm 'Bắt đầu Scan' để thu thập dữ liệu.")

# ==============================
# LOGIC CHÍNH
# ==============================

if filtered_df.empty:
    if (
        "traffic_data" in st.session_state
        and not st.session_state["traffic_data"].empty
    ):
        st.warning("Bộ lọc hiện tại không tìm thấy kết quả nào.")
    else:
        st.write("")  # Placeholder
else:
    # ==============================
    # TRANG 1: DASHBOARD TỔNG QUAN
    # ==============================
    if menu == "📊 Dashboard Tổng quan":
        st.header("📊 Tổng quan Lưu lượng LAN")

        c1, c2, c3, c4 = st.columns(4)
        total_bytes = filtered_df["length"].sum()
        c1.metric("Tổng dung lượng", f"{total_bytes/1024:.2f} KB")
        c2.metric("Tổng số gói tin", f"{len(filtered_df):,}")
        avg_len = total_bytes / len(filtered_df) if len(filtered_df) > 0 else 0
        c3.metric("Kích thước TB", f"{avg_len:.0f} Bytes")
        # capture_time lấy từ slider, mang tính ước lượng
        if len(filtered_df) > 1:
            t_start = pd.to_datetime(filtered_df["timestamp"].min())
            t_end = pd.to_datetime(filtered_df["timestamp"].max())
            total_time = (t_end - t_start).total_seconds()
            c4.metric("Time tổng", f"{total_time:.2f} s")
        else:
            c4.metric("Time tổng", "0 s")

        st.subheader("📈 Băng thông theo thời gian thực")
        if not filtered_df.empty:
            df_chart = filtered_df.copy()
            # Convert timestamp to standard datetime if needed
            df_chart["timestamp"] = pd.to_datetime(df_chart["timestamp"])
            df_chart["sec"] = df_chart["timestamp"].dt.strftime("%H:%M:%S")
            time_df = df_chart.groupby("sec")["length"].sum().reset_index()

            fig_area = px.area(
                time_df,
                x="sec",
                y="length",
                labels={"length": "Traffic (Bytes)", "sec": "Time"},
                title="Lưu lượng (Bytes/s)",
                color_discrete_sequence=["#00CC96"],
            )
            fig_area.update_layout(template="plotly_dark", height=350)
            st.plotly_chart(fig_area, use_container_width=True)

        c_left, c_right = st.columns(2)
        with c_left:
            st.subheader("🏆 Top Nguồn (Source)")
            top_src = filtered_df["src_ip"].value_counts().head(5)
            st.dataframe(top_src, use_container_width=True)

        with c_right:
            st.subheader("🎯 Top Đích (Destination)")
            top_dst = filtered_df["dst_ip"].value_counts().head(5)
            st.dataframe(top_dst, use_container_width=True)

    # ==============================
    # TRANG 2: PHÂN TÍCH LUỒNG
    # ==============================
    elif menu == "🔀 Phân tích Luồng (Flows)":
        st.header("🔀 Phân tích Luồng dữ liệu")
        st.subheader("🗺️ Bản đồ luồng (Sankey Diagram)")

        if len(filtered_df) > 0:
            flow_df = (
                filtered_df.groupby(["src_ip", "dst_ip", "application"])
                .size()
                .reset_index(name="count")
            )
            flow_df = flow_df.sort_values("count", ascending=False).head(30)

            all_nodes = list(pd.concat([flow_df["src_ip"], flow_df["dst_ip"]]).unique())
            node_dict = {ip: i for i, ip in enumerate(all_nodes)}

            source_indices = [node_dict[src] for src in flow_df["src_ip"]]
            target_indices = [node_dict[dst] for dst in flow_df["dst_ip"]]

            fig_sankey = go.Figure(
                data=[
                    go.Sankey(
                        node=dict(
                            pad=15,
                            thickness=20,
                            line=dict(color="black", width=0.5),
                            label=all_nodes,
                            color="blue",
                        ),
                        link=dict(
                            source=source_indices,
                            target=target_indices,
                            value=flow_df["count"],
                            color="rgba(0, 104, 201, 0.4)",
                        ),
                    )
                ]
            )
            fig_sankey.update_layout(height=500)
            st.plotly_chart(fig_sankey, use_container_width=True)

            st.subheader("🕸️ Ma trận trao đổi (Heatmap)")
            heatmap_data = pd.crosstab(filtered_df["src_ip"], filtered_df["dst_ip"])
            fig_heat = px.imshow(
                heatmap_data,
                labels=dict(x="Dst IP", y="Src IP", color="Count"),
                color_continuous_scale="Viridis",
                aspect="auto",
            )
            st.plotly_chart(fig_heat, use_container_width=True)

    # ==============================
    # TRANG 3: PHÂN TÍCH GÓI TIN
    # ==============================
    elif menu == "📦 Phân tích Gói tin (Stats)":
        st.header("📦 Thống kê Chi tiết")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Phân bố Protocol")
            fig_pie = px.pie(
                filtered_df, names="application", values="length", hole=0.4
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with c2:
            st.subheader("Top Ports")
            port_counts = (
                filtered_df[filtered_df["dst_port"] != 0]["dst_port"]
                .value_counts()
                .reset_index()
            )
            port_counts.columns = ["Port", "Count"]
            fig_bar = px.bar(
                port_counts.head(10), x="Port", y="Count", text="Count", color="Count"
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("Phân bố kích thước gói tin")
        fig_hist = px.histogram(
            filtered_df, x="length", nbins=30, color_discrete_sequence=["#FF4B4B"]
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    # ==============================
    # TRANG 4: SOI GÓI TIN (INSPECTOR)
    # ==============================
    elif menu == "🔍 Soi gói tin (Inspector)":
        st.header("🔍 Packet Inspector")

        col_sel, col_data = st.columns([1, 2])

        # Chuẩn bị view
        log_view = filtered_df[
            ["timestamp", "src_ip", "dst_ip", "application", "length"]
        ].copy()
        log_view["timestamp"] = pd.to_datetime(log_view["timestamp"]).dt.strftime(
            "%H:%M:%S.%f"
        )

        with col_sel:
            st.subheader("Logs")
            st.dataframe(
                log_view.sort_index(ascending=False),
                height=600,
                use_container_width=True,
            )

            # Chọn index theo iloc (vị trí dòng)
            max_idx = len(filtered_df) - 1
            pkt_id = st.number_input(
                "Chọn Index gói tin (0 - {}):".format(max_idx),
                min_value=0,
                max_value=max_idx,
                value=0,
            )

        with col_data:
            if not filtered_df.empty and 0 <= pkt_id < len(filtered_df):
                st.subheader(f"Chi tiết: Packet #{pkt_id}")
                pkt = filtered_df.iloc[pkt_id]

                st.markdown(
                    f"""
                <div style="padding: 15px; border-radius: 5px; border-left: 5px solid #00cc96; background-color: #262730;">
                    <span class="header-style">{pkt['transport']} / {pkt['application']}</span><br>
                    <b>Time:</b> {pkt['timestamp']}<br>
                    <b>Length:</b> {pkt['length']} Bytes<br>
                    <b>Flow:</b> {pkt['src_ip']} ➝ {pkt['dst_ip']}:{pkt['dst_port']}
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.divider()

                # [FIX] Hex Dump Logic
                st.markdown("**💾 Payload Hex Dump:**")
                payload_hex = pkt["payload"]

                if payload_hex and len(payload_hex) > 0:
                    # [FIX] Hiển thị đúng dữ liệu thật, không nhân bản
                    display_hex = payload_hex

                    hex_view_str = "Offset   Hex                                               ASCII\n"
                    hex_view_str += "-" * 76 + "\n"

                    for i in range(0, len(display_hex), 32):
                        chunk = display_hex[i : i + 32]
                        offset = f"{i:04x}"

                        # Format Hex: tách từng cặp byte
                        hex_part = " ".join(
                            [chunk[j : j + 2] for j in range(0, len(chunk), 2)]
                        )

                        # Format ASCII
                        ascii_part = ""
                        for j in range(0, len(chunk), 2):
                            try:
                                val = int(chunk[j : j + 2], 16)
                                if 32 <= val <= 126:
                                    ascii_part += chr(val)
                                else:
                                    ascii_part += "."
                            except:
                                ascii_part += "."

                        # Căn chỉnh format
                        hex_view_str += f"0x{offset}   {hex_part:<48}  {ascii_part}\n"

                    st.markdown(
                        f'<div class="hex-view"><pre>{hex_view_str}</pre></div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.info("ℹ️ Gói tin này không có Payload (Raw Data).")
            else:
                st.info("Vui lòng chọn gói tin hợp lệ.")
