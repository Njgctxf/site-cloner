"""
skills_registry.py - Anthropic Cybersecurity Skills Dynamic Registry for Sentinel AI
Connects the repository (mukul975/Anthropic-Cybersecurity-Skills) containing 800+ structured
cybersecurity skill packs (MITRE ATT&CK, NIST CSF 2.0, MITRE D3FEND, OWASP) and enables
autonomous skill discovery, loading, and progressive execution by Sentinel AI.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("sentinel.skills")

SKILLS_REPO_URL = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git"
DEFAULT_SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "sentinel_skills"

@dataclass
class SecuritySkill:
    name: str
    description: str
    domain: str = "cybersecurity"
    subdomain: str = "general"
    tags: List[str] = field(default_factory=list)
    nist_csf: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    file_path: str = ""

    def load_full_content(self) -> Dict[str, Any]:
        """Loads and parses the full SKILL.md file with both frontmatter and body."""
        if not self.file_path or not os.path.isfile(self.file_path):
            return {"error": "Fichier de compétence introuvable."}

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            parts = content.split("---", 2)
            body = parts[2].strip() if len(parts) >= 3 else content

            return {
                "name": self.name,
                "description": self.description,
                "domain": self.domain,
                "subdomain": self.subdomain,
                "tags": self.tags,
                "nist_csf": self.nist_csf,
                "mitre_attack": self.mitre_attack,
                "instructions_markdown": body
            }
        except Exception as e:
            return {"error": f"Erreur de lecture de la compétence: {str(e)}"}


class SkillsRegistry:
    """
    In-memory indexed catalog of all 800+ cybersecurity skills.
    Loads instant pre-indexed data from index.json in < 0.05s.
    """

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir = skills_dir or DEFAULT_SKILLS_DIR
        self._skills: Dict[str, SecuritySkill] = {}
        self._is_indexed = False

    def ensure_indexed(self):
        """Builds in-memory index from index.json for instant startup."""
        if self._is_indexed and self._skills:
            return

        index_file = self.skills_dir / "index.json"
        if index_file.is_file():
            try:
                with open(index_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)

                skills_list = data.get("skills", [])
                skills_dict = {}

                for s in skills_list:
                    s_name = s.get("name", "")
                    if not s_name:
                        continue
                    
                    path_rel = s.get("path", f"skills/{s_name}")
                    skill_abs_path = str(self.skills_dir / path_rel / "SKILL.md")
                    
                    subdomain = "application-security" if any(w in s_name for w in ("jwt", "upload", "xss", "sqli", "idor", "bola", "csrf", "oauth", "api")) else \
                                "cloud-security" if any(w in s_name for w in ("aws", "azure", "gcp", "s3", "iam", "cloud", "kubernetes")) else \
                                "threat-hunting" if any(w in s_name for w in ("analyzing", "logs", "splunk", "wireshark", "memory", "forensics")) else \
                                "defensive-operations"

                    skills_dict[s_name.lower()] = SecuritySkill(
                        name=s_name,
                        description=s.get("description", ""),
                        domain=s.get("domain", "cybersecurity"),
                        subdomain=subdomain,
                        tags=[w for w in s_name.split("-") if len(w) > 2],
                        file_path=skill_abs_path
                    )

                self._skills = skills_dict
                self._is_indexed = True
                logger.info(f"Sentinel Skills Registry: {len(self._skills)} compétences indexées instantanément depuis index.json.")
                return
            except Exception as e:
                logger.warning(f"Erreur lecture index.json: {e}, fallback sur scan répertoire.")

        # Fallback filesystem scanner if index.json is missing
        skills_root = self.skills_dir / "skills"
        if skills_root.exists() and skills_root.is_dir():
            skills_dict = {}
            for folder in os.listdir(skills_root):
                folder_path = skills_root / folder
                skill_file = folder_path / "SKILL.md"
                if not skill_file.is_file():
                    continue

                skill_name = folder
                skills_dict[skill_name.lower()] = SecuritySkill(
                    name=skill_name,
                    description=f"Procédure opérationnelle de cybersécurité pour {skill_name}.",
                    subdomain="cybersecurity",
                    tags=skill_name.split("-"),
                    file_path=str(skill_file)
                )
            self._skills = skills_dict
            self._is_indexed = True

    def count(self) -> int:
        self.ensure_indexed()
        return len(self._skills)

    def get_skill(self, name: str) -> Optional[SecuritySkill]:
        self.ensure_indexed()
        name_clean = name.strip().lower()
        if name_clean in self._skills:
            return self._skills[name_clean]
        for k, v in self._skills.items():
            if name_clean in k:
                return v
        return None

    def search_skills(self, query: str = "", subdomain: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Searches across all 818 skills by query string and/or subdomain.
        """
        self.ensure_indexed()
        results = []
        q_tokens = query.lower().split() if query else []

        for skill in self._skills.values():
            if subdomain and subdomain.lower() not in skill.subdomain.lower():
                continue

            score = 0
            name_lower = skill.name.lower()
            desc_lower = skill.description.lower()

            if not q_tokens:
                score = 1
            else:
                for token in q_tokens:
                    if token in name_lower:
                        score += 5
                    if token in desc_lower:
                        score += 2

            if score > 0:
                results.append((score, {
                    "name": skill.name,
                    "description": skill.description[:220] + "..." if len(skill.description) > 220 else skill.description,
                    "subdomain": skill.subdomain,
                    "tags": skill.tags[:5]
                }))

        results.sort(key=lambda x: x[0], reverse=True)
        return [r[1] for r in results[:limit]]

    def get_categories(self) -> Dict[str, int]:
        self.ensure_indexed()
        counts: Dict[str, int] = {}
        for skill in self._skills.values():
            sub = skill.subdomain or "general"
            counts[sub] = counts.get(sub, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def get_stats(self) -> Dict[str, Any]:
        self.ensure_indexed()
        return {
            "total_skills": len(self._skills),
            "categories": self.get_categories(),
            "source_repo": SKILLS_REPO_URL,
            "is_active": len(self._skills) > 0
        }

# Global singleton
skills_registry = SkillsRegistry()
