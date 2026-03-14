# 🛡️ LLM-Powered SOC Analyst

<div align="center">

### Autonomous Security Investigation using Gemini LLM, Behavioral Analysis, and Retrieval-Augmented Generation (RAG)

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Gemini-FF6F00?style=for-the-badge&logo=google&logoColor=white)
![Vector DB](https://img.shields.io/badge/VectorDB-Chroma-6A1B9A?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-00C853?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-FFC107?style=for-the-badge)

</div>

---

# 📖 Overview

**LLM-Powered SOC Analyst** is an AI-driven cybersecurity investigation system designed to automate the analysis of security logs and reconstruct attack timelines.

Traditional SIEM platforms such as Splunk generate alerts but still require human analysts to manually investigate incidents. This project introduces an **autonomous investigation pipeline** that processes raw logs, extracts security events, analyzes behavior patterns, retrieves cybersecurity knowledge using RAG, and generates structured incident reports.

The system combines:

- **Behavioral analysis of log sequences**
- **Retrieval-Augmented Generation (RAG)**
- **MITRE ATT&CK threat intelligence**
- **Large Language Model reasoning (Gemini)**

The result is an AI system capable of **detecting multi-stage attacks and generating explainable incident reports.**

---

# 🚨 Problem Statement

Security Operations Centers face several challenges:

| Problem | Description |
|------|------|
| 📊 Massive log volumes | Security infrastructure generates huge volumes of logs |
| ⚠️ High false positives | Alert fatigue reduces analyst efficiency |
| 🔍 Manual investigation | SOC analysts spend significant time correlating events |
| ⏱️ Slow incident response | Delayed investigations increase risk |
| 🧠 Knowledge gap | Analysts must manually map threats to MITRE ATT&CK |

---

# ✅ Solution

The proposed system automates SOC investigations using AI.

Key capabilities include:

- **Log ingestion and normalization**
- **Security event extraction**
- **Behavioral sequence analysis**
- **Threat intelligence retrieval (MITRE ATT&CK)**
- **LLM-powered investigation**
- **Automated incident reporting**

---

# ✨ Key Features

| Feature | Description |
|------|------|
| 🤖 Autonomous Investigation | AI investigates security logs without human prompts |
| 📚 RAG Knowledge Base | MITRE ATT&CK knowledge grounding |
| 🔍 Behavioral Analysis | Detects suspicious sequences of activity |
| 🎯 Threat Mapping | Maps events to MITRE ATT&CK techniques |
| ⏳ Timeline Reconstruction | Reconstructs attack chains |
| 📄 Structured Reports | Generates actionable incident reports |
| 📊 Confidence Scoring | Provides severity and confidence levels |
| 💡 Explainable AI | Transparent reasoning for investigation results |
| 👥 Human-in-the-loop | SOC analysts review and validate findings |

---

# 🏗️ System Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                   🛡️ SOC ANALYST DASHBOARD                    │
│             Human Review & Response Actions                   │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                 📋 INCIDENT REPORT GENERATOR                  │
│  (Attack Timeline, MITRE Mapping, Severity, Remediation)      │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│                    🔍 INVESTIGATION ENGINE                    │
│  (Attack Correlation, Timeline Reconstruction, Reasoning)     │
└───────────────┬───────────────────────────────┬───────────────┘
                │                               │
┌───────────────▼───────────────┐   ┌───────────▼────────────────┐
│        🤖 GEMINI LLM          │   │       📚 RAG SYSTEM        │
│    Threat Reasoning Engine    │◄──► MITRE ATT&CK Knowledge DB │
└───────────────┬───────────────┘   └────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                   🧠 BEHAVIOR ANALYSIS LAYER                  │
│        Sequence Detection / LSTM (Optional)                  │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                    🔄 EVENT EXTRACTION ENGINE                 │
│      Converts raw logs into security-relevant events         │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                     📥 LOG NORMALIZATION                      │
│         Cleans and structures logs from multiple sources      │
└───────────────┬───────────────────────────────────────────────┘
                │
┌───────────────▼───────────────────────────────────────────────┐
│                        📡 LOG INGESTION                       │
│   osquery logs • authentication logs • network logs • system logs │
└───────────────────────────────────────────────────────────────┘
```

---

# ⚙️ Component Description

## 📡 Log Ingestion Layer

Collects raw telemetry from multiple sources:

- osquery endpoint logs
- authentication logs
- process execution logs
- network activity logs

---

## 📥 Log Normalization Layer

Converts heterogeneous logs into structured format.

Example:

Raw log

```
cmdline: sudo su
path: /usr/bin/sudo
```

Normalized event

```
privilege_escalation_attempt
```

---

## 🔄 Event Extraction Engine

Transforms logs into meaningful security events.

Example mapping:

| Raw Activity | Extracted Event |
|------|------|
| sudo command | Privilege Escalation |
| execution from /tmp | Suspicious Execution |
| outbound connection | Command & Control |

---

## 🧠 Behavior Analysis Layer

Analyzes sequences of events to detect suspicious activity.

Example sequence:

```
Login → Privilege Escalation → Suspicious Execution → External Connection
```

Optional models:

- LSTM sequence detection
- anomaly detection

---

## 📚 RAG Knowledge Base

The system uses Retrieval-Augmented Generation to ground reasoning in cybersecurity knowledge.

Components include:

- MITRE ATT&CK dataset
- vector embeddings
- ChromaDB vector store
- semantic retrieval

---

## 🤖 Gemini LLM Agent

Gemini performs the investigation by:

- analyzing event sequences
- mapping events to MITRE techniques
- reconstructing attack chains
- generating explainable analysis

---

## 🔍 Investigation Engine

Reconstructs attack progression.

Example:

```
Initial Access
→ Privilege Escalation
→ Execution
→ Command & Control
```

---

## 📋 Incident Report Generator

Generates structured output including:

- attack stage
- MITRE ATT&CK techniques
- severity level
- confidence score
- remediation recommendations

---

## 🛡️ SOC Analyst Dashboard

Human analysts can:

- review AI investigations
- validate attack detection
- initiate incident response

---

# 🔄 System Workflow

```
Security Logs
     ↓
Log Ingestion
     ↓
Log Normalization
     ↓
Event Extraction
     ↓
Behavior Analysis
     ↓
RAG Knowledge Retrieval
     ↓
LLM Investigation
     ↓
Attack Timeline Reconstruction
     ↓
Incident Report Generation
     ↓
SOC Analyst Review
```

---

# ⚙️ System Requirements

## Hardware

| Component | Minimum | Recommended |
|------|------|------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Storage | 5 GB | 10 GB |

---

## Software

Required tools:

- Python 3.10+
- Git
- pip
- virtual environment

Check version:

```
python --version
```

---

# 🚀 Installation

### Clone repository

```
git clone https://github.com/akash4426/LLM_Powered_SOC_Analyst.git
cd LLM_Powered_SOC_Analyst
```

---

### Create virtual environment

Linux / macOS

```
python3 -m venv venv
source venv/bin/activate
```

Windows

```
python -m venv venv
venv\Scripts\activate
```

---

### Install dependencies

```
pip install -r requirements.txt
```

---

### Configure environment variables

Create `.env`

```
GEMINI_API_KEY=your_api_key_here
```

---

### Run the API server

```
uvicorn backend.main:app --reload
```

Open browser

```
http://127.0.0.1:8000/docs
```

---

# 📊 Example Investigation

Input logs

```
User login from 10.0.0.5
sudo command executed
binary executed from /tmp
outbound connection to external IP
```

Generated investigation

```
Attack Chain:
Initial Access → Privilege Escalation → Execution → Command & Control

MITRE Techniques:
T1068, T1059, T1071

Severity: High
Confidence: 0.92

Recommended Actions:
- isolate host
- rotate credentials
- investigate lateral movement
```

---

# 📚 Technologies Used

- Python
- FastAPI
- Gemini LLM
- LangChain
- ChromaDB
- Sentence Transformers
- MITRE ATT&CK Dataset

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository  
2. Create feature branch  
3. Submit pull request  

---

# 📧 Contact

Author: **Akash**

GitHub:  
https://github.com/akash4426

---

# ⭐ Support

If you found this project useful, consider giving it a **star ⭐**

```
AI + Cybersecurity + LLM Reasoning
```

Made with ❤️ by Akash
