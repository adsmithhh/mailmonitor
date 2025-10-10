# Mail Monitor: Early Warning System for Risky Gmail Messages

Mail Monitor is a research-oriented tool that keeps a close eye on a Gmail inbox and calls out messages that look suspicious. It blends automation with human judgment: the software scans each message, calculates a risk score, and explains why a message feels off. Analysts, policy teams, and investigators can use the results to triage their inbox, document threats, and learn how adversaries try to slip past defenses.

---

## Why this matters

Email remains the easiest way for attackers to reach people. Phishing, fake invoices, and malware droppers all begin with a persuasive message. Mail Monitor turns raw email into structured intelligence:

* **Surfaces risky patterns** – highlights unusual domains, urgent language, or known malicious indicators.
* **Shows its work** – every score is backed by explanations and references so humans can review or override.
* **Creates an audit trail** – outputs structured JSON files that can feed case notes, spreadsheets, or dashboards.

The project started as a production prototype for a security team and has been generalized for broader research and policy analysis.

---

## What the system can do

| Capability | What it means for you |
| --- | --- |
| Gmail connectivity | Connects through Gmail IMAP or the official Gmail API (with OAuth) to read messages securely. |
| Multi-factor scoring | Combines several “mini-analysts” (keyword, domain reputation, threat intelligence checks) into a single confidence score from 0 (safe) to 1 (dangerous). |
| Configurable policy | Thresholds for "monitor", "flag", "quarantine", and "block" can be tuned in a YAML file to match your appetite for false positives. |
| Transparent reports | Produces JSON summaries that list the suspicious patterns found in each email. |
| Offline mode | Ships with stored data so you can test analytic rules without touching a live inbox. |

---

## How it works (conceptual overview)

1. **Ingest** – Mail Monitor connects to Gmail and pulls down a batch of messages (you choose the count).
2. **Analyze** – Each analyzer module inspects the message:
   * *Keyword analyzer* flags urgent phrases ("verify now", "wire transfer"), financial terminology, or phishing language.
   * *Domain analyzer* inspects links and sender addresses for typosquatting, strange top-level domains, or random strings that often indicate tracking and malware links.
   * *Threat intelligence analyzer* cross-references mock intelligence feeds (e.g., known bad senders, suspicious file hashes).
3. **Score & classify** – A weighted formula (default weights: keyword 25%, domain 35%, threat intelligence 40%) produces a total score. The system maps that score to an action recommendation.
4. **Explain** – For every email, the system records which analyzer raised concerns, what patterns matched, and how confident it is.

This design makes it easy to add new analyzers or adjust weights without rewriting the rest of the tool.

---

## Getting started (for collaboration with technical staff)

Mail Monitor is written in Python (3.8+) and expects collaborators to set up a virtual environment and install dependencies listed in `requirements.txt`. The headline steps are:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

To experiment without a live inbox, run the offline mode:

```bash
python mailmonitor_v3.py --offline
```

To connect to Gmail, a developer will need either:

* An **app password** for IMAP access, configured in `config_v3.yml`, or
* An **OAuth client** (via Google Cloud Console) saved as `credentials.json` for the Gmail API.

Detailed technical setup guides live in:

* [`GMAIL_API_SETUP.md`](GMAIL_API_SETUP.md) – step-by-step OAuth configuration.
* [`PRODUCTION_SUMMARY.md`](PRODUCTION_SUMMARY.md) – notes from the original deployment.

Policy teams can share these documents with their technical partners to operationalize the tool.

---

## Reading the results

Running a scan produces a structured JSON report (`mail_scan_<timestamp>.json`). Each entry includes:

* **Sender and subject** – for quick triage.
* **Total score and recommended action** – ALLOW, MONITOR, FLAG, QUARANTINE, or BLOCK.
* **Analyzer details** – why the tool reached its conclusion (e.g., “Suspicious pattern: [0-9a-f]{32,}” indicates a tracking hash).

These reports are ready for:

* Import into spreadsheets for incident tracking.
* Feeding downstream analytics (e.g., frequency of typosquatted domains over time).
* Briefing stakeholders on email threat trends.

---

## Responsible use & security notes

* **Protect credentials** – never store personal Gmail passwords in the repository. Use app passwords or OAuth tokens kept outside version control.
* **Respect privacy** – when scanning personal or sensitive inboxes, ensure compliance with your organization’s privacy policies.
* **Iterate carefully** – adjust thresholds in small increments and review the explanations to understand why alerts fire.

---

## Project roadmap & contributions

Mail Monitor already functions as a production-grade prototype. Future improvements we welcome contributions for include:

* Plugging in real threat intelligence feeds.
* Adding natural-language explanations for non-technical reviewers.
* Building a lightweight dashboard to visualize scan history.

If you are interested in collaborating, please open an issue or submit a pull request. The codebase is licensed under the permissive MIT License, making it suitable for academic, governmental, or commercial research initiatives.

---

**Mail Monitor helps teams learn faster from the threats that reach their inbox.**
