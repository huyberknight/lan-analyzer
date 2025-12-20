# clickhouse_db.py
import clickhouse_connect
import datetime as dt
import uuid

# ==============================
# KẾT NỐI CLICKHOUSE
# ==============================


def get_client():
    return clickhouse_connect.get_client(
        host="localhost",
        port=8123,
        username="default",
        password="",
        database="default",
    )


# ==============================
# KHỞI TẠO BẢNG
# ==============================


def init_tables(client):

    client.command(
        """
        CREATE TABLE IF NOT EXISTS lan_packets (
            session_id UUID,
            timestamp DateTime64(3),

            src_ip String,
            dst_ip String,

            src_mac String,
            dst_mac String,

            ip_version Enum8('IPv4' = 4, 'IPv6' = 6, 'ARP' = 1, 'Other' = 0),

            transport String,
            application String,

            src_port UInt16,
            dst_port UInt16,
            length UInt32,
            payload String
        ) ENGINE = MergeTree()
        ORDER BY timestamp
        """
    )

    client.command(
        """
        CREATE TABLE IF NOT EXISTS capture_sessions (
            session_id UUID,
            start_time DateTime64(3),
            end_time Nullable(DateTime64(3)),
            packet_limit UInt16,
            timeout UInt16,
            total_packets UInt32,
            total_bytes UInt64
        ) ENGINE = MergeTree()
        ORDER BY start_time
        """
    )


# ==============================
# SESSION
# ==============================


def create_session(client, packet_limit, timeout):

    session_id = uuid.uuid4()
    start_time = dt.datetime.now()

    client.insert(
        "capture_sessions",
        [[session_id, start_time, None, packet_limit, timeout, 0, 0]],
    )

    return session_id


def close_session(client, session_id, total_packets, total_bytes):

    end_time = dt.datetime.now()

    client.command(
        """
        ALTER TABLE capture_sessions
        UPDATE
            end_time = %(end)s,
            total_packets = %(pkts)s,
            total_bytes = %(bytes)s
        WHERE session_id = %(sid)s
        """,
        parameters={
            "end": end_time,
            "pkts": total_packets,
            "bytes": total_bytes,
            "sid": session_id,
        },
    )


# ==============================
# INSERT PACKET
# ==============================


def insert_packet(client, session_id, pkt):

    client.insert(
        "lan_packets",
        [
            [
                session_id,
                pkt["timestamp"],
                pkt["src_ip"],
                pkt["dst_ip"],
                pkt["src_mac"],
                pkt["dst_mac"],
                pkt["ip_version"],
                pkt["transport"],
                pkt["application"],
                pkt["src_port"],
                pkt["dst_port"],
                pkt["length"],
                pkt["payload"],
            ]
        ],
    )


# ==============================
# QUERY (DÙNG CHO STREAMLIT)
# ==============================


def get_sessions(client):
    return client.query_df(
        """
        SELECT session_id, start_time, total_packets
        FROM capture_sessions
        ORDER BY start_time DESC
        """
    )


def get_packets_by_session(client, session_id):
    return client.query_df(
        """
        SELECT *
        FROM lan_packets
        WHERE session_id = %(sid)s
        ORDER BY timestamp DESC
        """,
        parameters={"sid": session_id},
    )


def get_all_packets(client):
    return client.query_df(
        """
        SELECT *
        FROM lan_packets
        ORDER BY timestamp DESC
        """
    )
