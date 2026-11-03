"""
sentinel - Intelligent Cybersecurity Agent & Multi-LLM Orchestrator
"""

from .models import AgentMessage, AgentResponse, ToolCall, ToolResult
from .providers import get_provider, LLMProvider
from .guardian import guardian, SentinelGuardian, SecurityViolation
from .agent import SentinelAgent, SENTINEL_SYSTEM_PROMPT
from .storage import (
    init_sentinel_tables,
    get_sentinel_config,
    save_sentinel_config,
    list_conversations,
    create_conversation,
    get_conversation_messages,
    save_message,
    delete_conversation,
)
from .skills_registry import skills_registry, SkillsRegistry, SecuritySkill
from .asset_registry import (
    init_asset_tables,
    create_project,
    list_projects,
    register_asset,
    list_assets,
    get_asset,
    grant_authorization,
    revoke_authorization,
    is_target_in_universal_scope,
    VALID_ASSET_TYPES,
    VALID_TEST_TYPES,
)
from .shield import (
    emergency_shield,
    EmergencyShield,
    ShieldTier,
    init_shield_tables,
)

__all__ = [
    "AgentMessage",
    "AgentResponse",
    "ToolCall",
    "ToolResult",
    "get_provider",
    "LLMProvider",
    "guardian",
    "SentinelGuardian",
    "SecurityViolation",
    "SentinelAgent",
    "SENTINEL_SYSTEM_PROMPT",
    "init_sentinel_tables",
    "get_sentinel_config",
    "save_sentinel_config",
    "list_conversations",
    "create_conversation",
    "get_conversation_messages",
    "save_message",
    "delete_conversation",
    "skills_registry",
    "SkillsRegistry",
    "SecuritySkill",
    "init_asset_tables",
    "create_project",
    "list_projects",
    "register_asset",
    "list_assets",
    "get_asset",
    "grant_authorization",
    "revoke_authorization",
    "is_target_in_universal_scope",
    "VALID_ASSET_TYPES",
    "VALID_TEST_TYPES",
    "emergency_shield",
    "EmergencyShield",
    "ShieldTier",
    "init_shield_tables",
]
