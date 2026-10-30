"""
ci_cd.py - Continuous Integration & Continuous Deployment (CI/CD) Security Gate
Generates workflow definitions for GitHub Actions and GitLab CI/CD, enabling automated
security gating that breaks the build if critical vulnerabilities or low scores are detected.
"""

def generate_github_actions_workflow(target_url: str = "https://app.monentreprise.com", api_base_url: str = "https://cyberlab.mondomaine.com/__sc/security") -> str:
    """Generates a complete ready-to-commit GitHub Actions workflow file."""
    return f"""name: CyberLab Security Audit Gate

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-audit:
    name: DAST & SAST Vulnerability Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Trigger CyberLab Security Scan
        run: |
          echo "🚀 Déclenchement de l'audit de sécurité sur {target_url}..."
          RESPONSE=$(curl -s -w "\\n%{{http_code}}" -X POST "{api_base_url}/api/ci/scan" \\
            -H "Content-Type: application/json" \\
            -H "X-API-Key: ${{{{ secrets.CYBERLAB_API_KEY }}}}" \\
            -d '{{
              "target_url": "{target_url}",
              "min_score": 75,
              "fail_on_critical": true
            }}')

          HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
          BODY=$(echo "$RESPONSE" | sed '$d')

          echo "Réponse du Scanner CyberLab :"
          echo "$BODY" | jq . || echo "$BODY"

          if [ "$HTTP_CODE" -eq 200 ]; then
            echo "✅ Gate de sécurité VALIDÉE avec succès ! Déploiement autorisé."
            exit 0
          else
            echo "❌ Gate de sécurité ÉCHOUÉE (Code HTTP $HTTP_CODE). Des vulnérabilités bloquantes ont été identifiées !"
            exit 1
          fi
"""

def generate_gitlab_ci_yaml(target_url: str = "https://app.monentreprise.com", api_base_url: str = "https://cyberlab.mondomaine.com/__sc/security") -> str:
    """Generates a ready-to-paste GitLab CI stage."""
    return f"""stages:
  - test
  - security
  - deploy

cyberlab_dast_gate:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      echo "🚀 Lancement de l'audit CyberLab pour {target_url}..."
      RES=$(curl -s -w "\\n%{{http_code}}" -X POST "{api_base_url}/api/ci/scan" \\
        -H "Content-Type: application/json" \\
        -H "X-API-Key: $CYBERLAB_API_KEY" \\
        -d '{{"target_url": "{target_url}", "min_score": 75, "fail_on_critical": true}}')
      CODE=$(echo "$RES" | tail -n1)
      BODY=$(echo "$RES" | sed '$d')
      echo "$BODY" | jq . || echo "$BODY"
      if [ "$CODE" -ne 200 ]; then
        echo "❌ Échec de la politique de sécurité. Build bloqué."
        exit 1
      fi
  only:
    - main
    - merge_requests
"""
