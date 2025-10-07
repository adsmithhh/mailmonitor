# Simple Mail Monitor

Ultra-simple email threat detection for Gmail accounts.

## What it does

1. Connects to Gmail via IMAP
2. Scans recent emails for threats
3. Gives each email a risk score
4. Recommends action (ALLOW/MONITOR/FLAG/QUARANTINE/BLOCK)
5. Saves results to JSON

No fancy AI, no complex configuration - just basic threat patterns that work.

## Quick Start

```bash
# Install requirements
pip install -r requirements.txt

# Run scan
python mailmonitor.py your@gmail.com your_app_password 50

# Example output:
  1. ALLOW      (Score:  0) - Meeting reminder for tomorrow
  2. FLAG       (Score: 45) - URGENT: Verify your account now
  3. BLOCK      (Score: 85) - Wire transfer request - click here
```

## Setup

1. **Get Gmail App Password**
   - Go to Google Account settings
   - Enable 2-factor authentication
   - Generate app password for mail access

2. **Run the scanner**
   ```bash
   python mailmonitor.py username@gmail.com app_password 20
   ```

3. **Check results**
   - Results saved to `scan_results_YYYYMMDD_HHMMSS.json`
   - Console shows summary and threats

## Threat Detection

### Keywords (20 points each)
- urgent, verify, suspended, click here, act now
- wire transfer, bitcoin, cryptocurrency, refund
- update payment, confirm identity, security alert

### Domains (30 points each)
- .tk, .ml, .ga, .cf, .zip, .mov, .click

### Patterns (25 points each)  
- Shortened URLs (bit.ly/...)
- IP addresses (192.168.1.1)
- Tor domains (.onion)
- Defanged URLs (hxxp://)

### URLs (40 points each)
- Links to suspicious domains

## Risk Levels

- **0-19**: ALLOW (safe)
- **20-39**: MONITOR (watch)
- **40-59**: FLAG (review)
- **60-79**: QUARANTINE (hold)
- **80+**: BLOCK (dangerous)

## Files

- `mailmonitor.py` - Main scanner
- `requirements.txt` - Dependencies
- `config.json` - Optional settings
- `README.md` - This file

## Advanced Usage

```bash
# Scan last 100 emails
python mailmonitor.py user@gmail.com password 100

# Use config file (optional)
python mailmonitor.py --config config.json

# Quiet mode
python mailmonitor.py user@gmail.com password --quiet
```

## Security

- Never commit passwords to git
- Use app passwords, not regular passwords
- Consider environment variables for automation

## License

Simple and free - use however you want.