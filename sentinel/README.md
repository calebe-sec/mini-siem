# SOC Sentinel (soc-sentinel)

SOC Sentinel is an Intrusion Detection System (IDS) and Security Operations Center (SOC) log parsing and correlation engine. It uses rule-based detection, machine learning (Isolation Forest), and Large Language Models (LLM) for triage and threat analysis.

## Features

- **Multi-Source Log Parsers**: Authentication logs (auth.log), Apache, Nginx, and more.
- **Rule-Based Detection**: Ssh brute-force, sudo abuse, web scanning, and other customizable signatures.
- **Machine Learning Detection**: Anomaly detection using Isolation Forest and custom feature engineering.
- **LLM-Based Triage**: Automatic analysis and context generation via Anthropic/Ollama APIs.
- **MITRE ATT&CK Mapping**: Maps detected tactics and techniques directly to MITRE ATT&CK.
- **Multiple Reporting Formats**: Terminal alerts, JSON reports, and Markdown files.

## Project Structure

```text
soc-sentinel/
├── datasets/            # Training/test datasets (raw, processed, synthetic)
├── models/              # Saved model weights/scalers (joblib)
├── config/              # Configuration files (settings, rules, logging)
├── scripts/             # CLI entrypoints (train, generate logs, run pipeline)
├── tests/               # Automated unit tests
├── src/sentinel/        # Main source package
└── reports/             # Generated security reports
```

## Getting Started

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and fill in credentials:
   ```bash
   cp .env.example .env
   ```
4. Run the pipeline:
   ```bash
   python scripts/run_pipeline.py
   ```
