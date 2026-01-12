# MODLEK
ModSecurity Log Enrichment and Classification using ELK and Machine Learning

---

## About The Project

MODLEK is a security analytics and automation framework that integrates ModSecurity, the ELK Stack, and machine learning to analyze web traffic, classify suspicious requests, and assist in adaptive WAF rule hardening.

The system processes real web traffic inspected by ModSecurity, enriches it with structured data, classifies it using a trained ML model, and uses the results to support security decisions such as identifying highly triggered attack rules.

![Image](https://github.com/user-attachments/assets/72f6db4f-7bf9-4011-abd8-509b4c426106)

---

## Data Flow


```
┌─────────────────────┐
│   Web Traffic       │
│   (HTTP Requests)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────┐
│   ModSecurity (WAF Layer)           │
│  - SQLI Detection (CRS-942)         │
│  - LFI Detection (CRS-930)          │
│  - Custom Rules                     │
└──────────┬──────────────────────────┘
           │
           ├─────────────────────────────┐
           │                             │
           ▼                             ▼
┌──────────────────────┐    ┌─────────────────────────┐
│   Logstash Pipeline  │    │  Local Logs             │
│   (Log Processing)   │    │  (modsec-logs/)         │
└──────────┬───────────┘    └──────────┬──────────────┘
           │                           │
           ▼                           ▼
┌──────────────────────────────────────────────────────┐
│            Elasticsearch (Log Storage)               │
└──────────┬──────────────────────────────────────────┘
           │
    ┌──────┴──────────────┬─────────────────────┐
    │                     │                     │
    ▼                     ▼                     ▼
┌──────────────┐  ┌────────────────┐  ┌──────────────────┐
│ Python ML    │  │ Rule Updater   │  │  Visualization   │
│ (Detection)  │  │ (Automation)   │  │  (Dashboards)    │
└──────┬───────┘  └────────┬───────┘  └──────────────────┘
       │                   │
       ├─────────┬─────────┤
       ▼         ▼         ▼
┌──────────────────────────────────────┐
│   Email Alerts & Notifications       │
│   (Security Team)                    │
└──────────────────────────────────────┘
```

### Data Flow Explanation

1. Web traffic is inspected by ModSecurity which generates structured audit logs, and evaluated by Paranoia Level (PL) 1-2 CRS rules.
2. Logstash ingests these logs and stores them in Elasticsearch as unclassified_%{+YYYY.MM.dd.HH} documents.
3. A Python machine-learning pipeline fetches these documents, extracts features, and classifies each request as normal or malicious.
4. The classified results are stored in a classified_%{+YYYY.MM.dd.HH} Elasticsearch index.
5. Automation scripts analyze attack trends and frequently triggered rules to assist in ModSecurity rule enrichment (by managing triggered PL 3-4 rules).


---

## Getting Started

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)
- **Docker & Docker Compose** (for containerized deployment)
- **curl** (for downloading CRS rules)
- **git**

```
git clone https://github.com/maroof-I/modlek.git
cd modlek
```

#### Python Installation & Virtual Environment
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip3 install -r requirement.txt
   ```

#### Download OWASP CRS Rules

Use curl to download the SQLI and LFI Core Rule Set files to the root directory:

```bash
# Download SQL Injection Rule
curl -o REQUEST-942-APPLICATION-ATTACK-SQLI.conf \
  https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf

# Download Local File Inclusion Rule
curl -o REQUEST-930-APPLICATION-ATTACK-LFI.conf \
  https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
```

### Installation

#### Set Up Docker Containers
setting up a testing php app, and containers network.
```bash
docker compose -f testing-compose.yml up -d
```

```bash
docker compose -f modlek-compose.yml up -d
```

This starts:
- ModSecurity-enabled web server
- Elasticsearch
- Logstash
- Kibana (for visualization)

---

## Usage

#### Simulate Attach

```bash
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py -u "http://localhost:3010/search.php?q=q" --dbs
```

#### Running the Main Automation Script

```bash

# Navigate to the python scripts folder
cd ../python_script

# run the ML classification script
python3 ./machine_learning/fetch_and_preprocess_unclassified.py

# Run the main script
python3 ./automation/main.py

# if not set, ignore email error
# check rule added
cat custom_rules.conf
```

#### Available Python Scripts

**Main Automation Script** (`python_script/automation/main.py`)
   - Updates rules, processes classified logs, sends notifications

**Machine Learning** (`python_script/machine_learning/`)
   - `train_and_evaluate.py` - Train ML models
   - `fetch_and_preprocess_unclassified.py` - Preprocess log data
   - `process_http_data.py` - process CSIC data set

---

## Optimizations

#### Docker Containerization

Instead of running ELK stack as services, or compiling Modsecurity v3 in a single Virtual Machine. Running and managing containarised versions helped through the development process.

---

## Contact

🔗 LinkedIn: https://www.linkedin.com/in/m1--asim/
💻 GitHub: https://github.com/maroof-I
📝 Medium: https://medium.com/@maroof1.af