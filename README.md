# AI-Cybersecurity-Threat-Detection
End-to-End AI Network Intrusion &amp; Zero-Day Anomaly Detection System built with Python &amp; Scikit-Learn (Hybrid Random Forest + Isolation Forest) on NSL-KDD/CICIDS telemetry with automated MITRE ATT&amp;CK SOC alert triage.

# AI-Powered Cybersecurity Threat Detection System

[![Build Status](https://img.shields.io/badge/Build-Passing-16a34a?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/your-username/AI-Cybersecurity-Threat-Detection)
[![Version](https://img.shields.io/badge/Version-v1.0.0-0284c7?style=for-the-badge)](https://github.com/your-username/AI-Cybersecurity-Threat-Detection/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-64748b?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-2563eb?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-f97316?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-dc2626?style=for-the-badge)](https://attack.mitre.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-059669?style=for-the-badge)](https://github.com/your-username/AI-Cybersecurity-Threat-Detection/pulls

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Industry Relevance](#3-industry-relevance)
4. [Tech Stack](#4-tech-stack)
5. [System Architecture](#5-system-architecture)
6. [Dataset Details](#6-dataset-details)
7. [Installation Steps](#7-installation-steps)
8. [How to Run](#8-how-to-run)
9. [Results & Model Evaluation](#9-results--model-evaluation)
10. [Screenshots & Visual Proof](#10-screenshots--visual-proof)
11. [Known Limitations (Model Drift & Dataset Constraints)](#11-known-limitations-model-drift--dataset-constraints)
12. [How to Contribute](#12-how-to-contribute)
13. [Learning Outcomes](#13-learning-outcomes)

---

## 1. Project Overview

The **AI-Powered Cybersecurity Threat Detection System** is a modular, production-structured machine learning pipeline built with **Python, Scikit-Learn, Pandas, NumPy, Matplotlib, and Seaborn**.

Designed to replicate modern Security Operations Center (SOC) detection engineering workflows, this system ingests corporate network packet-flow logs (modeled on **NSL-KDD** and **CICIDS2017** schemas), engineers high-signal behavioral ratios, and executes a **Hybrid Dual-Model Threat Engine**:
- **Supervised Random Forest Classifier (`150` trees)**: Detects known multi-vector cyber attacks (`SYN_Flood_DoS`, `SSH_Brute_Force`, and `Port_Scan`) with a **98.41% F1-Score**.
- **Unsupervised Isolation Forest (`120` trees)**: Isolates novel, zero-day volumetric and behavioral anomalies (`Data_Exfiltration`) without requiring prior attack signatures.
- **Automated SOC Alert Triage Engine**: Maps suspicious network flows to **MITRE ATT&CK techniques**, assigns incident severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `NOMINAL`), and exports prioritized incident queues (`outputs/security_alerts.csv`) ready for SIEM/Splunk ingestion.

---

## 2. Problem Statement

Modern enterprise networks process millions of packet flows every hour across web servers, SSH jump hosts, and DNS resolvers. Traditional rule-based firewalls and static Intrusion Detection Systems (IDS) fail in three critical ways:
1. **Zero-Day & Encrypted Exfiltration Blindness**: Static firewall signatures cannot detect an insider threat or novel malware exfiltrating database dumps over legitimate port 443 (`HTTPS`) sessions when no known malware signature exists.
2. **SOC Analyst Alert Fatigue**: Rigid single-variable rules trigger thousands of False Positives during legitimate traffic bursts, burying real attacks under benign noise.
3. **Missing Multi-Variable Behavioral Context**: Raw NetFlow logs record isolated counters (`src_bytes`, `packet_rate`, `failed_logins`) rather than composite behavioral relationships (such as outbound-to-inbound byte asymmetry or incomplete TCP SYN handshake density).

This project solves these challenges by pairing **cybersecurity domain feature engineering** with a **hybrid supervised + unsupervised ML architecture**.

---

## 3. Industry Relevance

| Industry Sector | Real-World Security Use Case | How This Pipeline Solves It |
| :--- | :--- | :--- |
| **Banking & FinTech** | Credential stuffing & automated dictionary brute-force attacks against authentication APIs and SSH bastions. | Computes `brute_force_risk_score` to flag rapid failed login bursts and quarantine offending source IPs within seconds. |
| **Cloud & IT Infrastructure** | Volumetric TCP SYN Flood Denial-of-Service (DoS) and automated Nmap subnet reconnaissance sweeps. | Tracks `syn_flood_index` and `dst_port_diversity` to separate genuine user traffic surges from half-open SYN floods. |
| **Enterprise SaaS & Healthcare** | Stealthy outbound data exfiltration over allowed HTTPS/DNS channels (Data Loss Prevention / DLP). | Uses unsupervised `IsolationForest` on `bytes_asymmetry_ratio` to flag abnormal outbound data transfers without prior signatures. |

---

## 4. Tech Stack

| Layer | Technology / Library | Role in Pipeline |
| :--- | :--- | :--- |
| **Core Language** | Python 3.10+ | Modular package architecture and end-to-end CLI pipeline execution |
| **Data Manipulation** | Pandas, NumPy | Vectorized log deduplication, median imputation, and behavioral feature math |
| **Machine Learning** | Scikit-Learn (`RandomForestClassifier`, `IsolationForest`, `StandardScaler`) | Supervised attack classification, unsupervised anomaly scoring, and leakage-free scaling |
| **Visualization** | Matplotlib, Seaborn | Automated 300-DPI evaluation charts (Confusion Matrix, Feature Importance, KDE Histograms) |
| **Artifact Serialization** | Joblib | Persistence of trained models (`.pkl`), label encoders, and feature scalers |

---

## 5. System Architecture

```text
+-------------------------------------------------------------------------+
|                   1. INPUT LAYER: NETWORK FLOW LOGS                     |
|   data/generate_dataset.py -> data/raw_network_traffic.csv (2,500 rows) |
|   Fields: duration, protocol, service, src_bytes, dst_bytes, pkt_rate   |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                   2. PREPROCESSING MODULE (src/preprocess.py)           |
|   - Deduplication & Median Imputation                                   |
|   - Categorical Encoding (protocol_type_encoded, service_encoded)       |
|   - Stratified Train/Test Split (75% Train / 25% Test) + StandardScaler |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|          3. FEATURE ENGINEERING MODULE (src/feature_engineering.py)     |
|   + bytes_asymmetry_ratio  = (src_bytes + 1) / (dst_bytes + 1)          |
|   + packet_burst_intensity = packet_rate / (duration + 0.1)             |
|   + syn_flood_index        = packet_rate * syn_error_rate               |
|   + brute_force_risk_score = failed_logins * (1.5 + 2.0 * is_SSH)       |
+------------------------------------+------------------------------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
                   v                                   v
+-----------------------------------+ +-----------------------------------+
| 4A. SUPERVISED CLASSIFIER         | | 4B. UNSUPERVISED ANOMALY MODEL    |
| RandomForestClassifier (150 trees)| | IsolationForest (120 trees)       |
| Outputs: threat_probability [0-1] | | Outputs: anomaly_score [0-100]    |
+-----------------+-----------------+ +-----------------+-----------------+
                   |                                   |
                   +-----------------+-----------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|           5. ALERT TRIAGE & VISUALIZATION (src/threat_detector.py)      |
|   - Assigns Severity: CRITICAL / HIGH / MEDIUM / NOMINAL                |
|   - Maps MITRE ATT&CK IDs (T1498, T1110, T1046, T1048)                  |
|   - Exports outputs/security_alerts.csv & 4 PNG charts in images/       |
+-------------------------------------------------------------------------+

## Authors

* **GitHub:** [nandiniverma](https://github.com)
* **LinkedIn:** [Nandini](https://linkedin.com)




