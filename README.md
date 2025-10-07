# Mail Monitor

Production email threat detection for Gmail accounts.

## Installation

```bash
git clone <repository>
cd mailmonitor
pip install -r requirements.txt
```

## Usage

### With config file:
```bash
python mailmonitor.py gmail_config.ini
```

### With direct credentials:
```bash
python mailmonitor.py username@gmail.com app_password 100
```

## Configuration File Format

Create `gmail_config.ini`:
```ini
[gmail]
username = your@gmail.com
password = your_app_password

[monitoring]
max_emails_per_scan = 50

[thresholds]
quarantine = 0.7
flag = 0.5
block_sender = 0.9
```

## Output

Results saved to timestamped JSON files:
- Threat analysis for each email
- Risk scores and recommended actions
- Summary statistics

## Actions

- **ALLOW**: Safe email (score < 0.2)
- **MONITOR**: Low risk (score 0.2-0.5)
- **FLAG**: Medium risk (score 0.5-0.7)
- **QUARANTINE**: High risk (score 0.7-0.9)
- **BLOCK**: Critical threat (score > 0.9)

## Security

- Use Gmail app passwords only
- Store credentials securely
- Review quarantined emails manually