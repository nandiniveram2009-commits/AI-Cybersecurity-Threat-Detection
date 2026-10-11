import os
import numpy as np
import pandas as pd

def generate_cybersecurity_dataset(num_samples: int = 2500, random_state: int = 42) -> pd.DataFrame:
    np.random.seed(random_state)
    categories = np.random.choice(
        ["Normal", "SYN_Flood_DoS", "SSH_Brute_Force", "Port_Scan", "Data_Exfiltration"],
        size=num_samples,
        p=[0.65, 0.14, 0.10, 0.07, 0.04],
    )
    records = []
    base_timestamp = pd.Timestamp("2026-10-10 08:00:00")

    for i, category in enumerate(categories):
        timestamp = base_timestamp + pd.Timedelta(seconds=i * np.random.randint(1, 5))
        if category == "Normal":
            duration = np.random.exponential(scale=12.0)
            protocol_type = np.random.choice(["TCP", "UDP", "ICMP"], p=[0.78, 0.19, 0.03])
            service = np.random.choice(["HTTPS", "HTTP", "DNS", "SSH", "SMTP"], p=[0.50, 0.25, 0.15, 0.05, 0.05])
            src_bytes = int(np.random.lognormal(mean=7.2, sigma=0.8))
            dst_bytes = int(np.random.lognormal(mean=8.0, sigma=0.9))
            packet_rate = round(np.random.uniform(10, 180), 2)
            syn_error_rate = round(np.random.uniform(0.0, 0.06), 3)
            failed_logins = int(np.random.choice([0, 1], p=[0.97, 0.03]))
            dst_port_diversity = int(np.random.randint(1, 4))
            is_threat = 0
        elif category == "SYN_Flood_DoS":
            duration = np.random.uniform(0.01, 1.5)
            protocol_type = "TCP"
            service = np.random.choice(["HTTP", "HTTPS"], p=[0.7, 0.3])
            src_bytes = int(np.random.uniform(40, 160))
            dst_bytes = int(np.random.uniform(0, 60))
            packet_rate = round(np.random.uniform(1800, 5200), 2)
            syn_error_rate = round(np.random.uniform(0.78, 0.99), 3)
            failed_logins = 0
            dst_port_diversity = int(np.random.randint(1, 3))
            is_threat = 1
        elif category == "SSH_Brute_Force":
            duration = np.random.uniform(3.0, 45.0)
            protocol_type = "TCP"
            service = "SSH"
            src_bytes = int(np.random.uniform(600, 3200))
            dst_bytes = int(np.random.uniform(400, 1800))
            packet_rate = round(np.random.uniform(85, 420), 2)
            syn_error_rate = round(np.random.uniform(0.05, 0.25), 3)
            failed_logins = int(np.random.randint(6, 38))
            dst_port_diversity = 1
            is_threat = 1
        elif category == "Port_Scan":
            duration = np.random.uniform(0.05, 2.0)
            protocol_type = np.random.choice(["TCP", "UDP"], p=[0.85, 0.15])
            service = np.random.choice(["HTTP", "SSH", "SMTP", "DNS"])
            src_bytes = int(np.random.uniform(64, 256))
            dst_bytes = int(np.random.uniform(0, 120))
            packet_rate = round(np.random.uniform(450, 1400), 2)
            syn_error_rate = round(np.random.uniform(0.45, 0.85), 3)
            failed_logins = int(np.random.randint(0, 2))
            dst_port_diversity = int(np.random.randint(25, 120))
            is_threat = 1
        else:  # Data_Exfiltration
            duration = np.random.uniform(40.0, 240.0)
            protocol_type = np.random.choice(["TCP", "UDP"], p=[0.6, 0.4])
            service = np.random.choice(["HTTPS", "DNS"], p=[0.65, 0.35])
            src_bytes = int(np.random.uniform(250000, 1200000))
            dst_bytes = int(np.random.uniform(800, 4500))
            packet_rate = round(np.random.uniform(320, 950), 2)
            syn_error_rate = round(np.random.uniform(0.01, 0.10), 3)
            failed_logins = int(np.random.randint(0, 3))
            dst_port_diversity = int(np.random.randint(2, 8))
            is_threat = 1

        records.append({
            "flow_id": f"FLW-{10000 + i}",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f"192.168.{np.random.randint(1, 15)}.{np.random.randint(10, 250)}",
            "dst_ip": f"10.0.{np.random.randint(1, 5)}.{np.random.randint(5, 100)}",
            "duration": round(duration, 3),
            "protocol_type": protocol_type,
            "service": service,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "packet_rate": packet_rate,
            "syn_error_rate": syn_error_rate,
            "failed_logins": failed_logins,
            "dst_port_diversity": dst_port_diversity,
            "attack_category": category,
            "label": is_threat,
        })

    return pd.DataFrame(records)
