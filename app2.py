# app2.py
import streamlit as st
import pandas as pd

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

from views.dashboard import render_dashboard
from views.flows import render_flows
from views.stats import render_stats
from views.inspector import render_inspector

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
        st.write("")
else:
    if menu == "📊 Dashboard Tổng quan":
        render_dashboard(filtered_df)

    elif menu == "🔀 Phân tích Luồng (Flows)":
        render_flows(filtered_df)

    elif menu == "📦 Phân tích Gói tin (Stats)":
        render_stats(filtered_df)

    elif menu == "🔍 Soi gói tin (Inspector)":
        render_inspector(filtered_df)
