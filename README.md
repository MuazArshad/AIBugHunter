# AI Bug Hunting Agent 🤖🔒

An automated, AI-powered bug bounty hunting agent with a real-time cyberpunk web UI.

## Features

- 🛰 **Subdomain Enumeration** — Passive (crt.sh, HackerTarget) + Active DNS brute-force
- 🌐 **HTTP Probing** — Identifies live hosts and dangling CNAMEs
- 🔬 **7 Vulnerability Scanners** — All focused on low-hanging fruit:
  - Security Headers (CSP, HSTS, X-Frame-Options, etc.)
  - CORS Misconfiguration
  - Open Redirect
  - Reflected XSS
  - Information Disclosure (.env, .git, phpinfo, etc.)
  - Subdomain Takeover
  - SQL Injection (error-based)
- 🤖 **Multi-AI Triage** — Switch between Gemini, Claude, Grok, GPT-4o
- 📡 **Real-time WebSocket streaming** — Live terminal feed of scan progress
- 📊 **Structured Reports** — Export as Markdown or JSON

---

## Setup

### 1. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 3. Start the server

```bash
# Windows
start.bat

# Or manually
cd backend
python main.py
```

### 4. Open the UI

Visit: **http://localhost:8000**

---

## Project Structure

```
AiAgentForBugHunting/
├── backend/
│   ├── main.py                    # FastAPI entry point
│   ├── agent/
│   │   ├── orchestrator.py        # Main scan loop
│   │   ├── recon/                 # Subdomain + DNS modules
│   │   ├── scanners/              # 7 vulnerability scanner modules
│   │   └── ai_providers/          # Gemini, Claude, Grok, OpenAI
│   ├── models/                    # Pydantic data models
│   ├── utils/                     # HTTP client, report generator
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/ (app.js, scanner.js, report.js)
├── .env.example
└── README.md
```

---

## Adding API Keys

Edit your `.env` file:

```env
GEMINI_API_KEY=your_gemini_key_here
CLAUDE_API_KEY=your_claude_key_here
GROK_API_KEY=your_grok_key_here
OPENAI_API_KEY=your_openai_key_here
```

You only need to add the keys for the AI providers you want to use.

---

## Legal & Ethics ⚠️

This tool is for **authorized security testing only**. Always obtain **explicit written permission** before scanning any system. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

Only use this tool on:
- Your own systems
- Bug bounty programs where you're an authorized participant
- Systems where you have explicit written authorization
