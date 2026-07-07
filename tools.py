"""tools.py — Tool registry for agent-striker.

Set TOOL_MOCK_MODE=true in .env (or environment) to run without real binaries.
Mock outputs are realistic representations of what each tool actually returns.
"""

import os
import json
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit, parse_qsl, urlencode

# Defensive: load .env here too, so MOCK_MODE is read correctly even if this
# module ever gets imported before another module's load_dotenv() call runs
# (this is exactly what used to happen via agent.py's old import order).
from dotenv import load_dotenv
load_dotenv()

MOCK_MODE: bool = os.getenv("TOOL_MOCK_MODE", "false").lower() == "true"

# Folder where script-based tools (xsstrike, smuggler, ssrfmap, sstimap) are
# git-cloned. Binary tools (httpx-toolkit, sqlmap, dalfox, crlfuzz) are
# expected to already be on PATH via apt/go install — see README for exact
# install commands for each.
TOOLS_DIR = os.path.expanduser(os.getenv("TOOLS_DIR", "~/tools"))


def _script_path(folder: str, script: str) -> str:
    """Build the path to a cloned tool's entry-point script under TOOLS_DIR."""
    return os.path.join(TOOLS_DIR, folder, script)


# ── Base class ────────────────────────────────────────────────────────────────

class BaseTool:
    name: str = ""
    def run(self, target: str, **kwargs) -> str:
        raise NotImplementedError


# ── httpx ─────────────────────────────────────────────────────────────────────

class HttpxTool(BaseTool):
    name = "httpx"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "url": target, "status_code": 200,
                "title": "Demo App", "technologies": ["React", "Node.js"],
                "server": "nginx/1.18.0", "waf": None,
                "response_headers": {"X-Frame-Options": "SAMEORIGIN"}
            })
        # On Kali, ProjectDiscovery's httpx is packaged as "httpx-toolkit",
        # NOT "httpx" — that name is already taken by the python3-httpx
        # library, and calling "httpx" can silently invoke the wrong program.
        result = subprocess.run(
            ["httpx-toolkit", "-u", target, "-json", "-tech-detect", "-title", "-status-code"],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout or result.stderr


# ── sqlmap ────────────────────────────────────────────────────────────────────

class SqlmapTool(BaseTool):
    name = "sqlmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "injectable_params": ["id", "user_id"],
                "technique": "UNION-based",
                "dbms": "MySQL 8.0",
                "confirmed": True,
                "risk_level": "HIGH",
                "payload": "1 UNION SELECT NULL,NULL,version()--"
            })
        param = kwargs.get("param", "")
        # NOTE: sqlmap has no --output-format=json flag (a previous version
        # of this code passed one, which would crash on the real binary).
        # sqlmap only prints human-readable text; that's fine, we just
        # return the raw text either way.
        args = ["sqlmap", "-u", target, "--batch", "--level=3", "--risk=2"]
        if param:
            args.append(f"--data={param}")
        result = subprocess.run(
            args,
            capture_output=True, text=True, timeout=240
        )
        return result.stdout or result.stderr


# ── xsstrike ──────────────────────────────────────────────────────────────────

class XsstrikeTool(BaseTool):
    name = "xsstrike"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "vulnerable_params": ["q", "search"],
                "payload": "<script>alert(document.cookie)</script>",
                "reflected": True,
                "context": "HTML attribute",
                "confidence": 0.92
            })
        # XSStrike is a script, not an installed binary — run it via python3.
        # NOTE: --json does NOT mean "give me JSON output" for this tool; it
        # means "treat POST --data as a JSON body". There is no JSON output
        # mode, so we just capture its normal text output.
        script = _script_path("XSStrike", "xsstrike.py")
        result = subprocess.run(
            ["python3", script, "-u", target, "--skip-dom"],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout or result.stderr


# ── dalfox ────────────────────────────────────────────────────────────────────

class DalfoxTool(BaseTool):
    name = "dalfox"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "findings": [
                    {
                        "param": "returnUrl",
                        "payload": "\"><img src=x onerror=alert(1)>",
                        "type": "reflected_xss",
                        "severity": "HIGH",
                        "confirmed": True
                    }
                ]
            })
        # NOTE: dalfox's structured-output flag is a recent addition and its
        # exact accepted values ("jsonl" confirmed, "json" not) aren't stable
        # enough to depend on here, so we just capture its normal text output.
        result = subprocess.run(
            ["dalfox", "url", target],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout or result.stderr


# ── smuggler ──────────────────────────────────────────────────────────────────

class SmugglerTool(BaseTool):
    name = "smuggler"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "vulnerable": True,
                "technique": "CL.TE",
                "evidence": "Timeout differential detected on malformed chunked request",
                "backend_server": "gunicorn/20.1.0",
                "risk": "CRITICAL"
            })
        # NOTE: smuggler has no --json flag (a previous version of this code
        # passed one, which would crash: "unrecognized argument --json").
        script = _script_path("smuggler", "smuggler.py")
        result = subprocess.run(
            ["python3", script, "-u", target],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout or result.stderr


# ── ssrfmap ───────────────────────────────────────────────────────────────────

class SsrfmapTool(BaseTool):
    name = "ssrfmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "ssrf_found": True,
                "param": "url",
                "internal_host_reached": "169.254.169.254",
                "cloud_metadata_exposed": True,
                "evidence": "AWS IMDSv1 metadata returned via url= parameter"
            })
        # NOTE: SSRFmap does NOT take a plain target URL — it needs a raw
        # HTTP request FILE (-r) plus the name of the parameter to fuzz (-p).
        # A previous version of this code passed the target URL directly as
        # the -r value, which would never have worked. This builds that
        # request file on the fly from the target URL.
        param = kwargs.get("param")
        parts = urlsplit(target)
        query_pairs = parse_qsl(parts.query)
        if not param:
            # Default to the first query parameter found, or "url" if none.
            param = query_pairs[0][0] if query_pairs else "url"
        if not any(k == param for k, _ in query_pairs):
            query_pairs.append((param, "CHANGEME"))
        new_query = urlencode(query_pairs)
        path = parts.path or "/"
        request_line = f"GET {path}?{new_query} HTTP/1.1" if new_query else f"GET {path} HTTP/1.1"
        raw_request = (
            f"{request_line}\r\n"
            f"Host: {parts.netloc}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        script = _script_path("SSRFmap", "ssrfmap.py")
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        try:
            tmp.write(raw_request)
            tmp.close()
            result = subprocess.run(
                ["python3", script, "-r", tmp.name, "-p", param, "-m", "readfiles,portscan"],
                capture_output=True, text=True, timeout=120
            )
            return result.stdout or result.stderr
        finally:
            os.unlink(tmp.name)


# ── tplmap ────────────────────────────────────────────────────────────────────

class TplmapTool(BaseTool):
    # NOTE: the original epinna/tplmap is explicitly marked "no longer
    # maintained" by its own author and has Python-2-only parts. We run
    # SSTImap under the hood instead — an actively maintained Python 3
    # rewrite built specifically as "a modern alternative to tplmap" — while
    # keeping this class/registry key named "tplmap" so nothing elsewhere
    # in the project (agent.py's tool names, EXPLOIT_TOOLS, etc.) needs to
    # change.
    name = "tplmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "ssti_found": True,
                "engine": "Jinja2",
                "param": "template",
                "rce_possible": True,
                "test_payload": "{{7*7}}",
                "response": "49"
            })
        script = _script_path("SSTImap", "sstimap.py")
        result = subprocess.run(
            ["python3", script, "-u", target, "-s"],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout or result.stderr


# ── crlfuzzer ─────────────────────────────────────────────────────────────────

class CrlfuzzerTool(BaseTool):
    # NOTE: there's no well-maintained tool literally named "crlfuzzer".
    # The real, actively maintained, Kali-packaged tool for this job is
    # "crlfuzz" (no "er") by dwisiswant0 — a single `sudo apt install
    # crlfuzz` away. We run that binary here, keeping this class/registry
    # key named "crlfuzzer" for API stability with the rest of the project.
    name = "crlfuzzer"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "crlf_found": True,
                "param": "redirect",
                "injected_header": "X-Injected: crlf-test",
                "payload": "%0d%0aX-Injected:%20crlf-test",
                "severity": "MEDIUM"
            })
        result = subprocess.run(
            ["crlfuzz", "-u", target],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout or result.stderr


# ── Registry ──────────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, type[BaseTool]] = {
    "httpx":     HttpxTool,
    "sqlmap":    SqlmapTool,
    "xsstrike":  XsstrikeTool,
    "dalfox":    DalfoxTool,
    "smuggler":  SmugglerTool,
    "ssrfmap":   SsrfmapTool,
    "tplmap":    TplmapTool,
    "crlfuzzer": CrlfuzzerTool,
}
