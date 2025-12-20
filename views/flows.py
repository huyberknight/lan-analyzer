# pages/flows.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def render_flows(filtered_df):
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
