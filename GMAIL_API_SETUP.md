# Gmail API Setup Guide

## 🔑 **Activating Gmail API for Enhanced Features**

### **Current Status:**
- ✅ **IMAP Version Working** - Your current setup with app password
- 🔄 **Gmail API Available** - Enhanced features with proper setup

### **Why Use Gmail API?**
- 📋 **Labels Management** - Read/modify Gmail labels
- 🚨 **Auto Actions** - Mark as spam, move to folders
- 📊 **Enhanced Metadata** - Message IDs, thread info
- 🔒 **Better Security** - OAuth instead of passwords

---

## 📋 **Setup Steps:**

### **1. Google Cloud Console**
```
1. Go to: https://console.cloud.google.com/
2. Create new project: "Mail Monitor"
3. Enable APIs:
   - Navigation Menu → APIs & Services → Library
   - Search "Gmail API" → Click → Enable
```

### **2. Create Credentials**
```
1. APIs & Services → Credentials
2. + Create Credentials → OAuth 2.0 Client ID
3. Configure consent screen (if prompted):
   - User Type: External
   - App name: "Mail Monitor"
   - User support email: adsmithhh64@gmail.com
4. Create OAuth Client:
   - Application type: Desktop application
   - Name: "Mail Monitor Desktop"
5. Download JSON → Save as "credentials.json" in C:\mailmonitor\
```

### **3. Install Dependencies**
```bash
cd C:\mailmonitor
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

### **4. Test API Connection**
```bash
python gmail_api_monitor.py gmail_config.ini --api 10
```

### **5. First Run (One-time Setup)**
```
1. Browser will open automatically
2. Sign in to adsmithhh64@gmail.com
3. Grant permissions to "Mail Monitor"
4. token.pickle will be saved for future use
```

---

## 🔄 **Usage Comparison:**

### **IMAP Mode (Current):**
```bash
python mailmonitor_v3.py gmail_config.ini 50
```

### **Gmail API Mode (Enhanced):**
```bash
python gmail_api_monitor.py gmail_config.ini --api 50
```

---

## 📊 **Feature Comparison:**

| Feature | IMAP | Gmail API |
|---------|------|-----------|
| Read emails | ✅ | ✅ |
| Threat detection | ✅ | ✅ |
| No setup needed | ✅ | ❌ |
| Mark as spam | ❌ | ✅ |
| Label management | ❌ | ✅ |
| Message threading | ❌ | ✅ |
| Rate limits | Low | High |
| Security | App password | OAuth |

---

## 🛠️ **Current Recommendation:**

**Keep using IMAP for now** - it's working perfectly for threat detection.

**Add Gmail API later** when you need:
- Automatic spam marking
- Label-based organization
- Integration with other Google services

---

## 📁 **Files Created:**
- ✅ `gmail_api_monitor.py` - Enhanced API version
- ✅ `requirements.txt` - Updated with API dependencies
- ✅ `GMAIL_API_SETUP.md` - This setup guide

Your current IMAP setup is production-ready. Gmail API adds extra features but requires more setup.