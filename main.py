"""main.py — FastAPI entry point for agent-striker (Team 5, port 8005).

Endpoints:
  POST /agents/agent-striker/tasks  — accepts prompt + target + context, returns structured JSON
  GET  /health                      — returns agent status and tool allowlist
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from agent import run_react_agent

load_dotenv()

AGENT_ID = "agent-striker"
VERSION  = "1.0.0"

# Tools this agent is permitted to call (enforced inside agent.py as well)
TOOL_ALLOWLIST = [
    "httpx",
    "sqlmap",
    "xsstrike",
    "dalfox",
    "smuggler",
    "ssrfmap",
    "tplmap",
    "crlfuzzer",
]

app = FastAPI(title="agent-striker", version=VERSION)


class TaskRequest(BaseModel):
    prompt: str
    target: str
    context: dict = {}


@app.post("/agents/{agent_id}/tasks")
def run_task(agent_id: str, req: TaskRequest):
    # Deliberately a sync "def", not "async def": run_react_agent() is a slow,
    # blocking call (LLM round-trips, subprocess calls in real mode, and even
    # input() in real HITL mode). If this were "async def", that blocking call
    # would freeze FastAPI's single event loop, and every other request
    # (including /health) would hang until this one finished. A sync def lets
    # FastAPI hand it to a background thread automatically, so the server
    # can serve other requests concurrently.
    if agent_id != AGENT_ID:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_id}")
    try:
        result = run_react_agent(
            prompt=req.prompt,
            target=req.target,
            context=req.context,
        )
        return result
    except Exception as exc:
        return {
            "agent_id": AGENT_ID,
            "status": "failed",
            "response": {
                "summary": f"Agent error: {str(exc)}",
                "findings": [],
                "hitl_log": [],
                "action_log": [],
            },
        }


@app.get("/health")
async def health():
    return {
        "agent_id": AGENT_ID,
        "status": "ok",
        "version": VERSION,
        "tool_allowlist": TOOL_ALLOWLIST,
        "mock_mode": os.getenv("TOOL_MOCK_MODE", "false").lower() == "true",
    }
