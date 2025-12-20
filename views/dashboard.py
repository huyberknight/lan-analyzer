# pages/dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px


def render_dashboard(filtered_df):
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
