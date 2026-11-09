"""
models.py - Sentinel AI Data Structures & Tool Interfaces
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Dict[str, Any]
    # Opaque signature some providers (e.g. Gemini's "thinking" models) attach to a
    # functionCall part; it must be echoed back unchanged on the next turn or the
    # API rejects the request. Unused by providers that don't need it.
    thought_signature: Optional[str] = None

@dataclass
class ToolResult:
    tool_call_id: str
    name: str
    result: Any
    is_error: bool = False
    evidence: Optional[Dict[str, Any]] = None

@dataclass
class AgentMessage:
    role: str  # 'user', 'assistant', 'system', 'tool'
    content: str
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@dataclass
class AgentResponse:
    content: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    raw_response: Optional[Any] = None
    finish_reason: Optional[str] = None
