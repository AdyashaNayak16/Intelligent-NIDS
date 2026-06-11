from collections import defaultdict
import time
import numpy as np

flows = defaultdict(
    lambda: {
        "start_time": time.time(),
        "last_seen": time.time(),

        "fwd_packets": 0,
        "bwd_packets": 0,

        "fwd_bytes": 0,
        "bwd_bytes": 0,

        "packet_lengths": [],

        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "psh_count": 0,

        "destination_port": 0
    }
)


def update_flow(
    src_ip,
    dst_ip,
    protocol,
    packet_len,
    dst_port=None,
    tcp_flags=None
):

    flow_id = (
        src_ip,
        dst_ip,
        protocol
    )

    flow = flows[flow_id]

    flow["last_seen"] = time.time()

    flow["fwd_packets"] += 1
    flow["fwd_bytes"] += packet_len

    flow["packet_lengths"].append(
        packet_len
    )

    if dst_port is not None:
        flow["destination_port"] = dst_port

    if tcp_flags is not None:

        if tcp_flags & 0x02:
            flow["syn_count"] += 1

        if tcp_flags & 0x10:
            flow["ack_count"] += 1

        if tcp_flags & 0x04:
            flow["rst_count"] += 1

        if tcp_flags & 0x08:
            flow["psh_count"] += 1

    flow_duration = (
        flow["last_seen"]
        - flow["start_time"]
    )

    total_bytes = (
        flow["fwd_bytes"]
        + flow["bwd_bytes"]
    )

    total_packets = (
        flow["fwd_packets"]
        + flow["bwd_packets"]
    )

    flow_bytes_per_sec = (
        total_bytes
        / max(flow_duration, 0.001)
    )

    flow_packets_per_sec = (
        total_packets
        / max(flow_duration, 0.001)
    )

    packet_mean = np.mean(
        flow["packet_lengths"]
    )

    packet_std = np.std(
        flow["packet_lengths"]
    )

    avg_packet_size = np.mean(
        flow["packet_lengths"]
    )

    return {
        "Destination Port":
            flow["destination_port"],

        "Flow Duration":
            flow_duration,

        "Total Fwd Packets":
            flow["fwd_packets"],

        "Total Backward Packets":
            flow["bwd_packets"],

        "Total Length of Fwd Packets":
            flow["fwd_bytes"],

        "Total Length of Bwd Packets":
            flow["bwd_bytes"],

        "Flow Bytes/s":
            flow_bytes_per_sec,

        "Flow Packets/s":
            flow_packets_per_sec,

        "Packet Length Mean":
            packet_mean,

        "Packet Length Std":
            packet_std,

        "SYN Flag Count":
            flow["syn_count"],

        "ACK Flag Count":
            flow["ack_count"],

        "RST Flag Count":
            flow["rst_count"],

        "PSH Flag Count":
            flow["psh_count"],

        "Average Packet Size":
            avg_packet_size
    }