"""Learning center content of the security module (OWASP lessons with a quiz each)."""

MODULES = [
    {
        "id": "owasp_a03",
        "title": "A03:2021 — Injections (SQLi, Command, LDAP)",
        "difficulty": "Intermédiaire",
        "duration": "25 min",
        "summary": "Comprendre comment les requêtes non assainies permettent l'exécution d'instructions arbitraires sur la base de données.",
        "key_takeaways": [
            "Toujours utiliser des requêtes préparées (Prepared Statements / Paramétrage).",
            "Ne jamais concaténer de chaînes dans les requêtes SQL.",
            "Appliquer le principe de moindre privilège aux comptes de base de données."
        ],
        "quiz": {
            "question": "Quelle est la méthode la plus efficace pour prévenir les injections SQL ?",
            "options": [
                "Supprimer manuellement les guillemets simples des entrées",
                "Utiliser des requêtes préparées avec passage de paramètres",
                "Crypter les requêtes SQL dans le code client",
                "Augmenter le délai d'expiration de la session"
            ],
            "answer_index": 1,
            "explanation": "Les requêtes préparées garantissent que le moteur de base de données traite les entrées strictement comme des données littérales et non du code exécutable."
        }
    },
    {
        "id": "owasp_a01",
        "title": "A01:2021 — Défaillance des Contrôles d'Accès (IDOR, BOLA)",
        "difficulty": "Avancé",
        "duration": "30 min",
        "summary": "Analyser comment l'absence de vérification des permissions sur un ID permet à un utilisateur d'accéder aux données d'autrui.",
        "key_takeaways": [
            "Ne jamais faire confiance à l'ID fourni par le client dans l'URL ou le corps JSON.",
            "Valider systématiquement l'appartenance de la ressource à l'utilisateur connecté.",
            "Adopter un modèle RBAC (Role-Based Access Control) robuste."
        ],
        "quiz": {
            "question": "Que signifie la vulnérabilité IDOR (Insecure Direct Object Reference) ?",
            "options": [
                "Une injection de code dans la mémoire du serveur",
                "L'accès direct à une ressource sans vérifier si l'utilisateur y a droit",
                "Un déni de service sur le pare-feu",
                "Une erreur dans le certificat SSL"
            ],
            "answer_index": 1,
            "explanation": "L'IDOR se produit lorsqu'une application utilise un identifiant direct vers un objet en base sans valider si le demandeur en est le propriétaire légitime."
        }
    },
    {
        "id": "owasp_headers",
        "title": "Défense en Profondeur — En-têtes HTTP & Cookies Sécurisés",
        "difficulty": "Fondamental",
        "duration": "20 min",
        "summary": "Mettre en place une protection défensive robuste au niveau du protocole HTTP.",
        "key_takeaways": [
            "Toujours positionner HttpOnly pour bloquer le vol de cookie par XSS.",
            "Activer le flag Secure pour garantir la confidentialité sur le réseau.",
            "Configurer Content-Security-Policy pour bloquer l'injection de scripts tiers."
        ],
        "quiz": {
            "question": "Quel attribut de cookie empêche le vol de session via une faille Cross-Site Scripting (XSS) ?",
            "options": [
                "Secure",
                "HttpOnly",
                "SameSite=None",
                "Domain=.local"
            ],
            "answer_index": 1,
            "explanation": "Le flag HttpOnly interdit formellement à JavaScript (document.cookie) de lire la valeur du cookie, neutralisant ainsi son exfiltration par XSS."
        }
    }
]
