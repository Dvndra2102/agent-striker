# agent-striker — Team 5

**Students:** Sai Siddharth Davuluri, Samantula Devendra Supreeth  
**Port:** 8005  
**Agent ID:** `agent-striker`  
**Role:** F4 Active Scan (exploit validation) — the last stage of the pipeline

---

## What This Project Actually Is

Imagine you're a security tester hired to find vulnerabilities in a web app.
Normally you'd manually decide: "first let me check if the site is up, then
map out its pages, then look for secrets, then try to break it." That's slow
and depends entirely on your experience.

Obsidia automates that entire thought process using an AI agent. Instead of
you deciding what to do next, a **language model (LLM)** reads what the
previous tool found and reasons about what to run next — just like a
security expert would.

The five teams build five specialist agents, each covering one stage:

```
Scout (F1)          Mapper (F2)         Analyst (F3)
"Is it live?"  →   "What's on it?"  →  "Any secrets?"
     ↓
Prober (F4 safe)              Striker (F4 exploit) ← YOU ARE HERE
"Where can we attack?"   →   "Confirm & validate the attack"
```

**Your agent (Striker)** takes the findings from Prober — "hey, this URL
might be SQLi injectable" — and actually tries the exploit to confirm it.
Because exploit tools can do real damage, Striker has a **HITL gate**
(Human-In-The-Loop): it must ask for approval before running any exploit.

The AI reasoning framework used is called **ReAct** (Reason + Act). The LLM
sees the task, picks a tool, reads the tool's output, reasons again, picks
another tool, and so on until it has enough to write a final answer. This is
not a fixed script — the LLM decides the order dynamically.

---

## How Intent Tracking Works

Every tool call appends an entry to an `action_log` list:

```json
{
  "tool": "sqlmap",
  "target": "https://target.com/api?id=1",
  "intent_is_malicious": true,
  "hitl_approved": true,
  "reasoning": "Validate SQLi on id parameter flagged by Prober.",
  "output_summary": "..."
}
```

`intent_is_malicious` is `true` for any exploit tool and `false` for
reconnaissance tools like httpx. The ReAct loop checks this list to:

- **Block** any exploit tool that was called without prior HITL approval
- **Stop early** if the loop detects unapproved malicious actions
- **Return** the full log in the response so you can audit every decision

---

## File Structure

```
agent-striker/
├── main.py              # FastAPI app — POST /tasks, GET /health
├── agent.py             # LangGraph ReAct agent — all the AI logic lives here
├── tools.py             # Tool registry (mock + real mode)
├── parsers/
│   └── httpx_parser.py  # Shared parser for httpx output
├── requirements.txt
├── .env.example         # Copy to .env and fill in values
└── README.md            # This file
```

---

## Setup — Step by Step

### Step 1: Set up your environment

You need either your **Windows machine** or your **Kali Linux VM**. Python
3.10+ is required. Open a terminal (on Kali: the terminal app; on Windows:
PowerShell or Command Prompt).

```bash
# Check Python version — should say 3.10 or higher
python3 --version

# Install dependencies
pip install -r requirements.txt --break-system-packages
```

If you get "externally-managed-environment" on Kali, add
`--break-system-packages` to the pip command.

---

### Step 2: Choose local Ollama or Ollama Cloud

You have two options for the LLM "brain". If your machine (or VM) doesn't have
much RAM, **use Ollama Cloud — skip straight to Step 3.** No local install
needed at all; your code talks to Ollama's servers over plain HTTPS.

**Option A — Ollama Cloud (recommended for low-RAM VMs):**
1. Sign up at `ollama.com`.
2. Go to `ollama.com/settings/keys` → **Add API Key** → copy the key (shown once).
3. That's it — nothing to install. Continue to Step 3.

**Option B — Local Ollama (only if your machine has enough RAM):**
```bash
curl -fsSL https://ollama.com/install.sh | sh   # Linux/Kali
# or download the Windows installer from https://ollama.com/download

ollama serve            # keep this terminal open
ollama pull llama3      # in a second terminal
```

---

### Step 3: Configure environment variables

```bash
cp env.example .env
```

Open `.env` and set, **for Ollama Cloud:**
```
TOOL_MOCK_MODE=true
OLLAMA_BASE_URL=https://ollama.com/v1
OLLAMA_MODEL=qwen3.5:cloud
OLLAMA_API_KEY=<paste the key you generated in Step 2>
```

or, **for local Ollama:**
```
TOOL_MOCK_MODE=true
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=llama3
OLLAMA_API_KEY=
```

---

### Step 4: Run the agent

```bash
uvicorn main:app --port 8005 --reload
```

You no longer need to prefix the command with `TOOL_MOCK_MODE=true` —
the `.env` file is now loaded before anything reads that variable, so the
file alone is enough.

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8005 (Press CTRL+C to quit)
```

---

### Step 5: Test it

**Check the health endpoint:**
```bash
curl http://localhost:8005/health
```

Expected response:
```json
{
  "agent_id": "agent-striker",
  "status": "ok",
  "version": "1.0.0",
  "tool_allowlist": ["httpx", "sqlmap", "xsstrike", "dalfox", "smuggler", "ssrfmap", "tplmap", "crlfuzzer"],
  "mock_mode": true
}
```

**Send a task (standalone, no upstream context):**
```bash
curl -X POST http://localhost:8005/agents/agent-striker/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Validate SQLi and XSS vulnerabilities on the target.",
    "target": "http://testphp.vulnweb.com/",
    "context": {}
  }'
```

**Send a task with Prober context (pipeline mode):**
```bash
curl -X POST http://localhost:8005/agents/agent-striker/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Validate the injection points found by Prober. Require HITL before each exploit.",
    "target": "http://testphp.vulnweb.com/",
    "context": {
      "summary": "Prober found injectable param id= on /listproducts.php and reflected XSS on search.php?q=",
      "findings": [
        {"type": "sqli_candidate", "url": "http://testphp.vulnweb.com/listproducts.php?cat=1"},
        {"type": "xss_candidate",  "url": "http://testphp.vulnweb.com/search.php?test=query"}
      ]
    }
  }'
```

**Expected response shape:**
```json
{
  "agent_id": "agent-striker",
  "status": "completed",
  "response": {
    "summary": "Confirmed SQLi on /listproducts.php?cat= via UNION technique...",
    "findings": [
      {
        "tool": "sqlmap",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "summary": "Injectable param confirmed: MySQL 8.0, UNION-based"
      }
    ],
    "hitl_log": [
      {
        "tool": "hitl_approve(sqlmap)",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "intent_is_malicious": true,
        "hitl_approved": true,
        "reasoning": "Validate SQLi on cat parameter flagged by Prober.",
        "output_summary": "APPROVED (mock): sqlmap cleared on ..."
      }
    ],
    "action_log": [ ... ]
  }
}
```

---

## Installing the real tools (for TOOL_MOCK_MODE=false)

Everything below is for your Kali VM. Run once, then set `TOOL_MOCK_MODE=false`
in `.env`. Each command was verified against the tool's current, actively
maintained documentation as of mid-2026 — two of the original eight tools
turned out to be unmaintained or nonexistent by that name and have been
swapped for their real, current equivalents (noted below).

### 1. Binary tools (installed once, available system-wide)

```bash
sudo apt update
sudo apt install -y sqlmap httpx-toolkit crlfuzz golang-go
```

- **sqlmap** — ships with Kali; the `apt install` above just ensures it's current.
- **httpx-toolkit** — this is ProjectDiscovery's `httpx`, packaged under this
  name on Kali specifically to avoid clashing with the unrelated `python3-httpx`
  library, which also installs a program called `httpx`. `tools.py` already
  calls it by its correct name.
- **crlfuzz** — replaces the originally-listed "crlfuzzer", which isn't a real,
  maintained tool under that name. `crlfuzz` is the actual actively-maintained
  Go tool for this job, and is directly `apt`-installable on Kali.
- **golang-go** — needed for dalfox below.

Dalfox isn't in the standard Kali repos, so install it via Go:
```bash
go install github.com/hahwul/dalfox/v2@latest
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
dalfox version   # confirms it's on PATH
```

### 2. Script-based tools (cloned into one folder)

These aren't installed system-wide — they're Python scripts you run directly.
Clone them all into the folder set by `TOOLS_DIR` in your `.env` (default `~/tools`):

```bash
mkdir -p ~/tools && cd ~/tools

git clone https://github.com/s0md3v/XSStrike
pip install -r XSStrike/requirements.txt --break-system-packages

git clone https://github.com/defparam/smuggler

git clone https://github.com/swisskyrepo/SSRFmap
pip install -r SSRFmap/requirements.txt --break-system-packages

git clone https://github.com/vladko312/SSTImap
```

**About that last one:** the project originally listed `tplmap`, but its own
author's repository says outright *"This project is no longer maintained"*
and parts of it are Python-2-only. `SSTImap` is an actively maintained
Python 3 rewrite built specifically as a modern replacement for tplmap, so
`tools.py` now runs that instead — the tool is still called `tplmap` in the
project's API (agent tool names, `EXPLOIT_TOOLS`, etc.), only what runs
underneath changed.

### 3. Verify everything

```bash
sqlmap --version
httpx-toolkit -version
crlfuzz -h
dalfox version
python3 ~/tools/XSStrike/xsstrike.py -h
python3 ~/tools/smuggler/smuggler.py -h
python3 ~/tools/SSRFmap/ssrfmap.py -h
python3 ~/tools/SSTImap/sstimap.py -h
```
If all eight print help/version text without errors, you're ready to flip
`TOOL_MOCK_MODE=false` in `.env` and restart `uvicorn`.

### A note on SSRFmap specifically

Unlike the other tools, SSRFmap doesn't take a plain target URL — it expects
a raw HTTP request **file** and the name of the parameter to fuzz. `tools.py`
now builds that request file automatically from whatever URL the agent
passes in. If the LLM knows which parameter is the actual SSRF candidate
(e.g. `url`, `redirect`, `file` — usually named in the Prober context), it
should pass that as `param`; otherwise the code guesses the first query
parameter it finds, which may not be the right one.

---

## Changelog — fixes applied

- **`agent.py`**: the LLM's `api_key` was reading a made-up env var name
  (`Obsidia_Test_API_Key`) that didn't exist in `.env`, so it silently fell
  back to a placeholder and Ollama Cloud would reject every request. Now
  reads `OLLAMA_API_KEY`, matching `.env`.
- **`agent.py` / `tools.py`**: `.env` was being loaded *after* `tools.py`
  was imported, so `TOOL_MOCK_MODE` could be read as `False` even with
  `TOOL_MOCK_MODE=true` sitting in `.env` — mock mode only worked if you
  also set the variable directly in your shell. Both files now load `.env`
  before anything reads from it.
- **`agent.py`**: the action log and HITL-approval set were plain module
  globals, shared across every request. Now stored per-request via
  `contextvars`, so concurrent requests can't leak state into each other.
- **`main.py`**: the task endpoint was `async def` but called a slow,
  blocking function directly, which would freeze the whole server for
  every other request while one task was running. Changed to a plain
  `def` so FastAPI runs it in a background thread.
- **`agent.py`**: `run_httpx` now actually uses `httpx_parser.parse_httpx()`
  to extract signal candidates, instead of the parser sitting unused.
- **`tools.py`**: `sqlmap`'s real-mode subprocess call could pass an empty
  string as a stray command-line argument when no `param` was given; the
  arg list is now built conditionally.
- **`env.example`**: `OLLAMA_BASE_URL` pointed at `https://cloud.ollama.com/v1`,
  which isn't a real Ollama Cloud address — the correct one is
  `https://ollama.com/v1`.
- **`tools.py`**: fixed real-mode (`TOOL_MOCK_MODE=false`) invocations for
  every tool, several of which used nonexistent CLI flags that would have
  crashed on first real run:
  - `httpx` → calls the correct Kali binary name `httpx-toolkit`.
  - `sqlmap` → removed `--output-format=json`, which doesn't exist.
  - `xsstrike` → now runs the cloned script via `python3`, dropped the
    misleading `--json` flag (it means "POST body is JSON", not "JSON output").
  - `dalfox` → removed an unverified `--format json` flag.
  - `smuggler` → now runs the cloned script via `python3`, dropped a
    `--json` flag that doesn't exist for this tool.
  - `ssrfmap` → complete rewrite. It never took a plain URL to begin with —
    it needs a raw HTTP request file and a parameter name. Added an adapter
    that builds that file automatically; `run_ssrfmap` now also accepts a
    `param` argument.
  - `tplmap` → swapped to run `SSTImap` under the hood, since the original
    tplmap is explicitly unmaintained and partly Python-2-only.
  - `crlfuzzer` → swapped to run the real `crlfuzz` binary, since no
    maintained tool named "crlfuzzer" exists.



When all five agents are running, chain them:

```python
import requests

target = "http://testphp.vulnweb.com/"

# Step 1: Scout fingerprints the target
scout = requests.post("http://localhost:8001/agents/agent-scout/tasks", json={
    "prompt": "Fingerprint the target.", "target": target, "context": {}
}).json()

# Step 2-4: Mapper → Analyst → Prober (each receives previous response as context)
# ... (other teams' agents)

# Step 5: Striker validates findings from Prober
striker = requests.post("http://localhost:8005/agents/agent-striker/tasks", json={
    "prompt": "Validate injection points from Prober. Use HITL before each exploit.",
    "target": target,
    "context": prober["response"]   # prober's response becomes our context
}).json()

print(striker)
```

---

## Tool Allowlist

Striker is only allowed to call these tools (enforced in `agent.py`):

| Tool | What it does | Malicious? |
|---|---|---|
| `httpx` | Verify target is live | No |
| `sqlmap` | Test SQL injection | **Yes — needs HITL** |
| `xsstrike` | Find and validate XSS | **Yes — needs HITL** |
| `dalfox` | Deep XSS scanning | **Yes — needs HITL** |
| `smuggler` | HTTP request smuggling | **Yes — needs HITL** |
| `ssrfmap` | Server-Side Request Forgery | **Yes — needs HITL** |
| `tplmap` | Template injection (SSTI) | **Yes — needs HITL** |
| `crlfuzzer` | CRLF injection | **Yes — needs HITL** |

The agent will **refuse** to run any exploit tool if `hitl_approve` was not
called first. In mock mode, approval is automatic and logged. In real mode,
it blocks and waits for you to type `approve` in the terminal.

---

## Switching to Real Tools

When you're ready to run real tools (lab targets only — never production):

1. Set `TOOL_MOCK_MODE=false` in `.env`
2. Make sure `sqlmap`, `dalfox`, `xsstrike` etc. are installed on your Kali VM
3. Only scan `testphp.vulnweb.com` or other instructor-approved lab targets

```bash
# Install common tools on Kali
sudo apt install sqlmap -y
pip install dalfox xsstrike --break-system-packages
```

---

## Common Problems

| Problem | Fix |
|---|---|
| `ollama: command not found` | Restart your terminal after installing Ollama |
| `Connection refused` on port 11434 | Run `ollama serve` in a separate terminal first |
| `externally-managed-environment` | Add `--break-system-packages` to pip commands |
| LLM returns generic text | Check that Ollama is running and the model name in `.env` matches what you pulled |
| Tool returns empty output | Set `TOOL_MOCK_MODE=true` — real binaries probably aren't installed |
| Agent calls exploit tool without HITL | This is blocked by design; the LLM should call `hitl_approve` first |
