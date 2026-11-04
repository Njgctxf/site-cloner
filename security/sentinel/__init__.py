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
from .system_engine import (
    audit_linux_server_config,
    audit_windows_server_config,
    audit_database_config,
)
from .remediation import (
    init_remediation_tables,
    create_remediation_plan,
    list_remediations,
    get_remediation,
    approve_remediation,
    reject_remediation,
    apply_remediation,
    rollback_remediation,
    verify_remediation_post_fix,
    STANDARD_REMEDIATION_TEMPLATES,
)
from .memory import (
    init_memory_tables,
    save_audit_memory,
    list_audit_memory,
    get_audit_memory,
    compare_audit_snapshots,
    record_architecture_knowledge,
    get_project_knowledge_context,
    sanitize_secrets,
)
from .reporting import (
    generate_consolidated_soc_report,
    generate_executive_html_report,
)
from .pentagi_engine import (
    pentagi_engine,
    PentAGIIntegrationEngine,
    PENTAGI_CAPABILITIES,
    init_pentagi_tables,
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
    "audit_linux_server_config",
    "audit_windows_server_config",
    "audit_database_config",
    "init_remediation_tables",
    "create_remediation_plan",
    "list_remediations",
    "get_remediation",
    "approve_remediation",
    "reject_remediation",
    "apply_remediation",
    "rollback_remediation",
    "verify_remediation_post_fix",
    "STANDARD_REMEDIATION_TEMPLATES",
    "init_memory_tables",
    "save_audit_memory",
    "list_audit_memory",
    "get_audit_memory",
    "compare_audit_snapshots",
    "record_architecture_knowledge",
    "get_project_knowledge_context",
    "sanitize_secrets",
    "generate_consolidated_soc_report",
    "generate_executive_html_report",
    "pentagi_engine",
    "PentAGIIntegrationEngine",
    "PENTAGI_CAPABILITIES",
    "init_pentagi_tables",
]
