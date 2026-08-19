"""Constants for SourceAgent."""

import os

# Load .env file before reading environment variables
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Application Info
APP_NAME = "SourceAgent"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = "RQ1: Semantic source/sink label recovery for monolithic firmware"

# Agent States
AGENT_STATE_IDLE = "idle"
AGENT_STATE_THINKING = "thinking"
AGENT_STATE_EXECUTING = "executing"
AGENT_STATE_WAITING_INPUT = "waiting_input"
AGENT_STATE_COMPLETE = "complete"
AGENT_STATE_ERROR = "error"

# Tool Categories
TOOL_CATEGORY_EXECUTION = "execution"
TOOL_CATEGORY_MCP = "mcp"

# Default Timeouts (in seconds)
DEFAULT_COMMAND_TIMEOUT = 300
DEFAULT_MCP_TIMEOUT = 60

# Ghidra Settings
LAUNCH_GHIDRA = os.environ.get("LAUNCH_GHIDRA", "0")
GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "")
JAVA_HOME = os.environ.get("JAVA_HOME", "")

# LLM Defaults (set SOURCEAGENT_MODEL in .env or shell)
DEFAULT_MODEL = os.environ.get(
    "SOURCEAGENT_MODEL"
)  # No fallback - requires configuration
DEFAULT_TEMPERATURE = 0.7
DEFAULT_MAX_TOKENS = 4096

# Agent Defaults
AGENT_MAX_ITERATIONS = int(os.environ.get("SOURCEAGENT_AGENT_MAX_ITERATIONS", "90"))
ORCHESTRATOR_MAX_ITERATIONS = int(
    os.environ.get("SOURCEAGENT_ORCHESTRATOR_MAX_ITERATIONS", "50")
)

# File Extensions
KNOWLEDGE_TEXT_EXTENSIONS = [".txt", ".md"]
KNOWLEDGE_DATA_EXTENSIONS = [".json"]

# MCP Transport Types
MCP_TRANSPORT_STDIO = "stdio"
MCP_TRANSPORT_SSE = "sse"

# Exit Commands
EXIT_COMMANDS = ["exit", "quit", "q", "bye"]
