# gmail_gate.py
import base64, time, sys, html
from typing import Dict, Any
from bs4 import BeautifulSoup

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# ⬇️ import your analyzer
from mailmonitor.enhanced_gmail_monitor import analyze_email

# ===== Config =====
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    # uncomment next if you want auto-labeling
    # "https://www.googleapis.com/auth/gmail.modify",
]
QUERY = 'is:unread newer_than:7d'   # tune as you like

# Optional auto-actions (requires gmail.modify scope)
ENABLE_LABELING = False
LABELS = {
    "ALLOW": "MAILMONITOR/ALLOW",
    "MONITOR": "MAILMONITOR/MONITOR",
    "FLAG": "MAILMONITOR/FLAG",
    "QUARANTINE": "MAILMONITOR/QUARANTINE",
    "BLOCK": "MAILMONITOR/BLOCK",
}

def _auth():
    creds = None
    if Path("token.json").exists():
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        open("token.json", "w").write(creds.to_json())
    return creds

from pathlib import Path
def _gmail_service():
    creds = _auth()
    return build("gmail", "v1", credentials=creds)

def _ensure_labels(svc):
    """Create labels if they don't exist. Only used when ENABLE_LABELING=True."""
    existing = svc.users().labels().list(userId="me").execute().get("labels", [])
    name_to_id = {l["name"]: l["id"] for l in existing}
    out = {}
    for _, name in LABELS.items():
        if name not in name_to_id:
            body = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
            created = svc.users().labels().create(userId="me", body=body).execute()
            name_to_id[name] = created["id"]
    # reverse map by action
    for action, name in LABELS.items():
        out[action] = name_to_id[name]
    return out

def _decode_part(part: Dict[str, Any]) -> str:
    data = part.get("body", {}).get("data")
    if not data:
        return ""
    decoded = base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="ignore")
    if part.get("mimeType", "").lower().startswith("text/html"):
        # strip HTML → text
        soup = BeautifulSoup(decoded, "html.parser")
        return soup.get_text(" ", strip=True)
    return decoded

def _get_message_text(msg: Dict[str, Any]) -> Dict[str, str]:
    payload = msg.get("payload", {})
    mime = payload.get("mimeType", "")
    body_txt = ""
    subj = ""
    frm = ""
    for h in (payload.get("headers") or []):
        n = h.get("name", "").lower()
        if n == "subject": subj = h.get("value", "")
        if n == "from": frm = h.get("value", "")
    if mime == "text/plain" or "text/plain" in mime:
        body_txt = _decode_part(payload)
    elif mime == "text/html" or "text/html" in mime:
        body_txt = _decode_part(payload)
    elif mime.startswith("multipart/"):
        parts = payload.get("parts") or []
        # prefer text/plain, else text/html
        plain = next((p for p in parts if p.get("mimeType","").startswith("text/plain")), None)
        htmlp = next((p for p in parts if p.get("mimeType","").startswith("text/html")), None)
        if plain: body_txt = _decode_part(plain)
        elif htmlp: body_txt = _decode_part(htmlp)
    return {"from": frm, "subject": subj, "body": body_txt}

def _list_unread_ids(svc, q: str):
    res = svc.users().messages().list(userId="me", q=q, maxResults=50).execute()
    return [m["id"] for m in res.get("messages", [])]

def _get_message(svc, msg_id: str):
    return svc.users().messages().get(userId="me", id=msg_id, format="full").execute()

def _apply_label(svc, msg_id: str, label_id: str):
    body = {"addLabelIds": [label_id], "removeLabelIds": []}
    svc.users().messages().modify(userId="me", id=msg_id, body=body).execute()

def run_once():
    svc = _gmail_service()
    label_map = {}
    if ENABLE_LABELING:
        label_map = _ensure_labels(svc)

    ids = _list_unread_ids(svc, QUERY)
    if not ids:
        print("No unread messages matching query.")
        return

    for mid in ids:
        msg = _get_message(svc, mid)
        doc = _get_message_text(msg)
        result = analyze_email(doc, cfg=None)  # uses your current config defaults
        risk = result.get("risk")
        action = result.get("recommended_action")
        print(f"[{mid}] {doc['subject'][:80]!r} → risk={risk} action={action}")

        if ENABLE_LABELING:
            label_id = label_map.get(action)
            if label_id:
                _apply_label(svc, mid, label_id)

if __name__ == "__main__":
    run_once()
