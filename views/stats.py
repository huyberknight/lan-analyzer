# pages/stats.py
import streamlit as st
import plotly.express as px


def render_stats(filtered_df):
    st.header("📦 Thống kê Chi tiết")

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Phân bố Protocol")
        fig_pie = px.pie(filtered_df, names="application", values="length", hole=0.4)
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.subheader("📡 Phân bố IP Version")
        fig_ipver = px.pie(filtered_df, names="ip_version", values="length", hole=0.4)
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
