# app2.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ipaddress
import requests
from scapy_sniffer import parse_packet, sniff_packets
from clickhouse_db import (
    get_client,
    init_tables,
    create_session,
    close_session,
    insert_packet,
    get_sessions,
    get_packets_by_session,
    get_all_packets,
)


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False


IPINFO_TOKEN = "434052a9178d5f"


@st.cache_data(ttl=3600)
def lookup_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
    r = requests.get(url, timeout=3)
    if r.status_code == 200:
        return r.json()
    return None


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
# 1.1 KẾT NỐI DATABASE
# ==============================
try:
    ch_client = get_client()
    init_tables(ch_client)
except Exception as e:
    st.error(f"❌ Không thể kết nối ClickHouse: {e}")
    st.stop()


# ==============================
# 2. XỬ LÝ DỮ LIỆU SCAPY
# ==============================
def generate_lan_traffic_from_scapy(iface=None, packet_limit=100, timeout=10):

    session_id = create_session(ch_client, packet_limit, timeout)

    progress_bar = st.progress(0)
    status_text = st.empty()

    packet_count = 0
    total_bytes = 0

    def on_packet(pkt):
        nonlocal packet_count, total_bytes

        parsed = parse_packet(pkt)
        insert_packet(ch_client, session_id, parsed)

        packet_count += 1
        total_bytes += parsed["length"]

        if packet_count % 2 == 0:
            progress_bar.progress(min(packet_count / packet_limit, 1.0))
            status_text.text(f"Đang bắt gói tin: {packet_count}/{packet_limit}")

    try:
        sniff_packets(
            iface=iface,
            packet_limit=packet_limit,
            timeout=timeout,
            on_packet=on_packet,
        )

        close_session(
            ch_client,
            session_id,
            total_packets=packet_count,
            total_bytes=total_bytes,
        )

        progress_bar.progress(1.0)
        status_text.text("Hoàn tất!")

    except PermissionError:
        st.error("❌ Cần quyền Administrator / Root")
    except Exception as e:
        st.error(f"❌ Lỗi Scapy: {e}")

    return session_id


# ==============================
# 3. SIDEBAR ĐIỀU HƯỚNG
# ==============================
with st.sidebar:
    st.title("🕸️ LAN Analyzer")
    # st.caption("Scapy Real-time Sniffer")
    st.markdown("---")

    # =====================
    # CẤU HÌNH SCAN
    # =====================
    st.subheader("⚙️ Cấu hình Bắt gói tin")

    target_iface = st.text_input("Interface (VD: eth0, Wi-Fi)", value="")
    packet_count = st.slider("Số lượng gói tối đa", 10, 500, 50)
    capture_time = st.slider("Thời gian timeout (giây)", 5, 60, 10)

    if st.button("🚀 Bắt đầu Scan", type="primary"):
        with st.spinner("Đang bắt gói tin..."):
            current_session = generate_lan_traffic_from_scapy(
                iface=target_iface,
                packet_limit=packet_count,
                timeout=capture_time,
            )
            # 🔑 lưu session vừa quét
            st.session_state["active_session"] = current_session
            st.session_state["view_mode"] = "📌 Đợt được chọn"
            st.success("✅ Hoàn tất thu thập dữ liệu")

    st.markdown("---")

    # =====================
    # DANH SÁCH SESSION
    # =====================
    sessions = get_sessions(ch_client)

    if sessions.empty:
        st.info("📂 Chưa có đợt thu thập nào")
        selected_session = None
    else:
        session_ids = sessions["session_id"].tolist()

        # 🔑 tự động chọn session vừa scan
        default_index = 0
        if "active_session" in st.session_state:
            try:
                default_index = session_ids.index(st.session_state["active_session"])
            except ValueError:
                pass

        selected_session = st.selectbox(
            "📂 Chọn đợt thu thập",
            options=session_ids,
            index=default_index,
            format_func=lambda x: (
                f"Session {str(x)[:8]} | "
                f"{sessions.loc[sessions.session_id == x, 'start_time'].values[0]}"
            ),
        )

    # =====================
    # CHẾ ĐỘ XEM
    # =====================
    view_mode = st.radio(
        "Chế độ xem",
        ["📌 Đợt được chọn", "📊 Tổng tất cả đợt"],
        key="view_mode",
    )

    # =====================
    # QUERY DỮ LIỆU
    # =====================
    if view_mode == "📌 Đợt được chọn" and selected_session is not None:
        df = get_packets_by_session(ch_client, selected_session)
    else:
        df = get_all_packets(ch_client)

    st.session_state["traffic_data"] = df

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

        filtered_df = df.copy()

        if "application" in df.columns:
            unique_apps = df["application"].unique()
            selected_apps = st.multiselect(
                "🖥️ Giao thức L7",
                unique_apps,
                default=unique_apps,
            )
            filtered_df = filtered_df[filtered_df["application"].isin(selected_apps)]
        if "ip_version" in df.columns:
            ip_versions = df["ip_version"].unique().tolist()
            selected_ip_versions = st.multiselect(
                "🌐 Phiên bản IP", ip_versions, default=ip_versions
            )
            filtered_df = filtered_df[
                filtered_df["ip_version"].isin(selected_ip_versions)
            ]
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
            c4.metric("Thời gian", f"{total_time:.2f} s")
        else:
            c4.metric("Thời gian", "0 s")

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
            top_src = filtered_df["src_ip"].value_counts().head(5).reset_index()
            top_src.columns = ["Source IP", "Packets"]
            st.dataframe(top_src, use_container_width=True)

        with c_right:
            st.subheader("🎯 Top Đích (Destination)")
            top_dst = filtered_df["dst_ip"].value_counts().head(5).reset_index()
            top_dst.columns = ["Destination IP", "Packets"]
            st.dataframe(top_dst, use_container_width=True)

        c_left, c_right = st.columns(2)

        with c_left:
            st.subheader("🔌 Top MAC nguồn")
            top_src_mac = filtered_df["src_mac"].value_counts().head(5).reset_index()
            top_src_mac.columns = ["Source MAC", "Packets"]
            st.dataframe(top_src_mac, use_container_width=True)

        with c_right:
            st.subheader("🎯 Top MAC đích")
            top_dst_mac = filtered_df["dst_mac"].value_counts().head(5).reset_index()
            top_dst_mac.columns = ["Destination MAC", "Packets"]
            st.dataframe(top_dst_mac, use_container_width=True)

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
            fig_sankey.update_layout(
                height=500, font=dict(size=20)  # 👈 áp dụng cho toàn bộ chữ
            )
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
            st.subheader("📡 Phân bố IP Version")
            fig_ipver = px.pie(
                filtered_df, names="ip_version", values="length", hole=0.4
            )

            st.plotly_chart(fig_ipver, use_container_width=True)

        c1, c2 = st.columns(2)
        with c1:
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
        with c2:
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
            [
                "timestamp",
                "src_mac",
                "dst_mac",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "ip_version",
                "application",
                "length",
            ]
        ].copy()
        log_view["timestamp"] = pd.to_datetime(log_view["timestamp"]).dt.strftime(
            "%H:%M:%S.%f"
        )

        log_view = log_view.rename(
            columns={
                "timestamp": "Timestamp",
                "src_mac": "Src MAC",
                "dst_mac": "Dst MAC",
                "src_ip": "Src IP",
                "dst_ip": "Dst IP",
                "src_port": "Src Port",
                "dst_port": "Dst Port",
                "ip_version": "IP Version",
                "application": "Application",
                "length": "Length",
            }
        )

        with col_sel:
            st.subheader("🖹 Logs")

            log_view_sorted = log_view.sort_index(ascending=False)

            st.dataframe(
                log_view_sorted,
                height=600,
                use_container_width=True,
            )

            # Chọn packet theo index thực trong DataFrame
            selected_idx = st.selectbox(
                "🔎 Chọn gói tin",
                options=log_view_sorted.index.tolist(),
                format_func=lambda i: (
                    f"#{i} | {log_view_sorted.loc[i, 'Timestamp']} | "
                    f"{log_view_sorted.loc[i, 'Src IP']} ➝ {log_view_sorted.loc[i, 'Dst IP']}"
                ),
            )

        with col_data:
            if not filtered_df.empty and selected_idx in filtered_df.index:
                st.subheader(f"Chi tiết gói tin (Packet ID: {selected_idx})")
                pkt = filtered_df.loc[selected_idx]

                st.markdown(
                    f"""
                <div style="padding: 15px; border-radius: 5px; border-left: 5px solid #00cc96;">
                    <span class="header-style">{pkt['transport']} / {pkt['application']}</span><br>
                    <b>Time:</b> {pkt['timestamp']}<br>
                    <b>Length:</b> {pkt['length']} Bytes<br>
                    <b>Flow:</b> {pkt['src_ip']} ➝ {pkt['dst_ip']}:{pkt['dst_port']}<br>
                    <b>MAC:</b> {pkt['src_mac']} ➝ {pkt['dst_mac']}<br>
                    <b>IP ({pkt['ip_version']}):</b> {pkt['src_ip']} ➝ {pkt['dst_ip']}<br>
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

        st.subheader("🌍 IP Intelligence")

        if "pkt" not in locals():
            st.info("🔎 Vui lòng chọn một gói tin để xem IP Intelligence")
            st.stop()

        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]

        c_ip1, c_ip2 = st.columns(2)

        # ===== SRC IP =====
        with c_ip1:
            st.markdown("### 🟢 Source IP")
            if is_public_ip(src_ip):
                info = lookup_ipinfo(src_ip)
                if info and "loc" in info:
                    lat, lon = map(float, info["loc"].split(","))
                    st.map(pd.DataFrame({"lat": [lat], "lon": [lon]}))

                    st.write(f"**IP:** {info.get('ip', 'N/A')}")
                    st.write(f"**Hostname:** {info.get('hostname', 'N/A')}")
                    st.write(f"**City:** {info.get('city', 'N/A')}")
                    st.write(f"**Region:** {info.get('region', 'N/A')}")
                    st.write(f"**Country:** {info.get('country', 'N/A')}")
                    st.write(f"**Location:** {info.get('loc', 'N/A')}")
                    st.write(f"**ASN / Org:** {info.get('org', 'N/A')}")
                    st.write(f"**Postal:** {info.get('postal', 'N/A')}")
                    st.write(f"**Timezone:** {info.get('timezone', 'N/A')}")

                else:
                    st.warning("Không lấy được thông tin IP.")
            else:
                st.info("📡 IP nội bộ (Private / LAN) – không có ASN & Geo")

        # ===== DST IP =====
        with c_ip2:
            st.markdown("### 🔵 Destination IP")
            if is_public_ip(dst_ip):
                info = lookup_ipinfo(dst_ip)
                if info and "loc" in info:
                    lat, lon = map(float, info["loc"].split(","))
                    st.map(pd.DataFrame({"lat": [lat], "lon": [lon]}))

                    st.write(f"**IP:** {info.get('ip', 'N/A')}")
                    st.write(f"**Hostname:** {info.get('hostname', 'N/A')}")
                    st.write(f"**City:** {info.get('city', 'N/A')}")
                    st.write(f"**Region:** {info.get('region', 'N/A')}")
                    st.write(f"**Country:** {info.get('country', 'N/A')}")
                    st.write(f"**Location:** {info.get('loc', 'N/A')}")
                    st.write(f"**ASN / Org:** {info.get('org', 'N/A')}")
                    st.write(f"**Postal:** {info.get('postal', 'N/A')}")
                    st.write(f"**Timezone:** {info.get('timezone', 'N/A')}")
                else:
                    st.warning("Không lấy được thông tin IP.")
            else:
                st.info("📡 IP nội bộ (Private / LAN) – không có ASN & Geo")
