# pages/inspector.py
import streamlit as st
import pandas as pd
import requests
import ipaddress


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


def render_inspector(filtered_df):
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
                hex_view_str = (
                    "Offset   Hex                                               ASCII\n"
                )
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
