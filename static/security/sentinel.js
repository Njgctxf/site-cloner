/**
 * sentinel.js - Interactive Client Controller for Sentinel AI Workspace
 */

let currentConversationId = null;
let currentProvider = "mock";

document.addEventListener("DOMContentLoaded", () => {
    loadConversations();
    loadProviderConfig();
    loadUserLlmProviders();
    loadKaliStatus();
    loadPentagiStatus();
    setupEventListeners();
});

function setupEventListeners() {
    const chatInput = document.getElementById("chatInput");
    const sendBtn = document.getElementById("sendBtn");
    const newChatBtn = document.getElementById("newChatBtn");
    const providerSelect = document.getElementById("providerSelect");
    const openByokBtn = document.getElementById("openByokBtn");
    const killSwitchBtn = document.getElementById("killSwitchBtn");

    sendBtn.addEventListener("click", () => sendMessage());
    chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    newChatBtn.addEventListener("click", () => startNewConversation());

    providerSelect.addEventListener("change", (e) => {
        currentProvider = e.target.value;
        document.getElementById("activeModelTag").textContent = `Modèle: ${e.target.options[e.target.selectedIndex].text}`;
        updateActiveProvider(currentProvider);
    });

    openByokBtn.addEventListener("click", (e) => {
        e.preventDefault();
        openByokModal();
    });

    killSwitchBtn.addEventListener("click", () => toggleKillSwitch());

    const openSkillsLibBtn = document.getElementById("openSkillsLibBtn");
    if (openSkillsLibBtn) {
        openSkillsLibBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openSkillsLib();
        });
    }

    const openKaliBtn = document.getElementById("openKaliBtn");
    if (openKaliBtn) {
        openKaliBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openKaliModal();
        });
    }

    const openScannersBtn = document.getElementById("openScannersBtn");
    if (openScannersBtn) {
        openScannersBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openScannersModal();
        });
    }

    const openShieldBtn = document.getElementById("openShieldBtn");
    if (openShieldBtn) {
        openShieldBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openShieldModal();
        });
    }

    const openPentagiBtn = document.getElementById("openPentagiBtn");
    if (openPentagiBtn) {
        openPentagiBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openPentagiModal();
        });
    }

    const openUserLlmBtn = document.getElementById("openUserLlmBtn");
    if (openUserLlmBtn) {
        openUserLlmBtn.addEventListener("click", (e) => {
            e.preventDefault();
            openByokModal();
        });
    }
}

async function loadConversations() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/conversations");
        const data = await res.json();
        const container = document.getElementById("conversationsContainer");
        container.innerHTML = "";

        if (!data.conversations || data.conversations.length === 0) {
            container.innerHTML = `<div style="color: #64748b; font-size: 0.75rem; text-align: center; padding: 1rem;">Aucun historique récent</div>`;
            return;
        }

        data.conversations.forEach((conv, index) => {
            const item = document.createElement("div");
            item.className = `conv-item ${conv.id === currentConversationId ? 'active' : ''}`;
            item.innerHTML = `
                <span class="conv-title"><i class="fa-regular fa-message" style="margin-right: 6px;"></i> ${escapeHtml(conv.title)}</span>
                <button onclick="deleteConv(event, '${conv.id}')" style="background: none; border: none; color: #64748b; cursor: pointer;">
                    <i class="fa-solid fa-trash-can"></i>
                </button>
            `;
            item.addEventListener("click", () => switchConversation(conv.id, conv.title));
            container.appendChild(item);

            if (index === 0 && !currentConversationId) {
                switchConversation(conv.id, conv.title);
            }
        });
    } catch (e) {
        console.error("Erreur chargement conversations", e);
    }
}

async function startNewConversation() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/conversations", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({title: "Nouvelle session d'audit"})
        });
        const data = await res.json();
        if (data.success) {
            currentConversationId = data.conversation_id;
            document.getElementById("chatTitle").textContent = "Nouvelle session d'audit";
            clearChatStream();
            loadConversations();
        }
    } catch (e) {
        console.error("Erreur création conversation", e);
    }
}

async function switchConversation(convId, title) {
    currentConversationId = convId;
    document.getElementById("chatTitle").textContent = title || "Session d'audit";
    document.querySelectorAll(".conv-item").forEach(el => el.classList.remove("active"));

    try {
        const res = await fetch(`/__sc/security/api/sentinel/conversations/${convId}`);
        const data = await res.json();
        const stream = document.getElementById("chatStream");
        stream.innerHTML = "";

        if (data.messages && data.messages.length > 0) {
            data.messages.forEach(msg => {
                appendMessageToUI(msg.role, msg.content, msg.tool_results);
            });
        }
        scrollChatToBottom();
    } catch (e) {
        console.error("Erreur chargement messages", e);
    }
}

async function deleteConv(e, convId) {
    e.stopPropagation();
    if (!confirm("Voulez-vous supprimer cette session d'audit ?")) return;

    try {
        await fetch(`/__sc/security/api/sentinel/conversations/${convId}`, { method: "DELETE" });
        if (currentConversationId === convId) {
            currentConversationId = null;
            clearChatStream();
        }
        loadConversations();
    } catch (err) {
        console.error("Erreur suppression", err);
    }
}

async function sendMessage() {
    const input = document.getElementById("chatInput");
    const text = input.value.trim();
    if (!text) return;

    input.value = "";
    appendMessageToUI("user", text);
    scrollChatToBottom();

    // Loading indicator
    const stream = document.getElementById("chatStream");
    const loaderId = "loader_" + Date.now();
    const loaderEl = document.createElement("div");
    loaderEl.id = loaderId;
    loaderEl.className = "msg-bubble msg-assistant";
    loaderEl.innerHTML = `
        <div class="avatar avatar-sentinel"><i class="fa-solid fa-spinner fa-spin"></i></div>
        <div class="msg-content" style="color: #94a3b8; font-style: italic;">
            Ulton AI analyse la requête et coordonne les outils sous contrôle du Guardian...
        </div>
    `;
    stream.appendChild(loaderEl);
    scrollChatToBottom();

    try {
        const res = await fetch("/__sc/security/api/sentinel/chat", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                message: text,
                conversation_id: currentConversationId,
                provider: currentProvider
            })
        });

        const data = await res.json();
        const loader = document.getElementById(loaderId);
        if (loader) loader.remove();

        if (data.error) {
            appendMessageToUI("assistant", `⚠️ Erreur : ${data.error}`);
        } else {
            if (data.conversation_id && !currentConversationId) {
                currentConversationId = data.conversation_id;
                loadConversations();
            }
            appendMessageToUI("assistant", data.reply, data.tools_executed);
        }
        scrollChatToBottom();
    } catch (e) {
        const loader = document.getElementById(loaderId);
        if (loader) loader.remove();
        appendMessageToUI("assistant", `⚠️ Erreur réseau : Impossible de contacter Ulton AI (${e.message})`);
        scrollChatToBottom();
    }
}

function sendQuickPrompt(promptText) {
    const input = document.getElementById("chatInput");
    input.value = promptText;
    sendMessage();
}

function appendMessageToUI(role, content, toolsExecuted = []) {
    const stream = document.getElementById("chatStream");
    const bubble = document.createElement("div");
    bubble.className = `msg-bubble msg-${role === 'user' ? 'user' : 'assistant'}`;

    const avatarHtml = role === 'user' 
        ? `<div class="avatar avatar-user"><i class="fa-solid fa-user"></i></div>`
        : `<div class="avatar avatar-sentinel"><i class="fa-solid fa-shield-halved"></i></div>`;

    let toolsHtml = "";
    if (toolsExecuted && toolsExecuted.length > 0) {
        toolsExecuted.forEach(t => {
            const hasFindings = t.result && t.result.findings && t.result.findings.length > 0;
            const badgeColor = hasFindings ? "#ef4444" : "#10b981";
            const badgeText = hasFindings ? `${t.result.findings.length} vulnérabilité(s) identifiée(s)` : "Vérification conforme";

            toolsHtml += `
                <div class="tool-card">
                    <div class="tool-header">
                        <span><i class="fa-solid fa-screwdriver-wrench"></i> ${escapeHtml(t.name)}</span>
                        <span style="color: ${badgeColor}; font-size: 0.72rem; font-weight: 600;">${badgeText}</span>
                    </div>
                    <div class="tool-details">
                        <strong>Paramètres:</strong> ${escapeHtml(JSON.stringify(t.arguments))}<br>
                        ${hasFindings ? `<div style="margin-top: 6px; color: #f87171;"><strong>Preuves techniques:</strong> ${escapeHtml(JSON.stringify(t.result.findings))}</div>` : ''}
                    </div>
                </div>
            `;
        });
    }

    bubble.innerHTML = `
        ${avatarHtml}
        <div class="msg-content">
            ${toolsHtml}
            <div>${formatMarkdown(content)}</div>
        </div>
    `;

    stream.appendChild(bubble);
}

function formatMarkdown(text) {
    if (!text) return "";
    let html = escapeHtml(text);
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.3); padding: 2px 5px; border-radius: 4px; font-family: monospace;">$1</code>');
    html = html.replace(/\n\n/g, '<br><br>');
    html = html.replace(/\n/g, '<br>');
    return html;
}

function escapeHtml(text) {
    if (!text) return "";
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function scrollChatToBottom() {
    const stream = document.getElementById("chatStream");
    stream.scrollTop = stream.scrollHeight;
}

function clearChatStream() {
    const stream = document.getElementById("chatStream");
    stream.innerHTML = `
        <div class="msg-bubble msg-assistant">
            <div class="avatar avatar-sentinel"><i class="fa-solid fa-robot"></i></div>
            <div class="msg-content">
                <p style="margin-top:0;">Nouvelle session démarrée. Quelle vérification de sécurité souhaitez-vous effectuer ?</p>
            </div>
        </div>
    `;
}

async function loadProviderConfig() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/config");
        const data = await res.json();
        currentProvider = data.active_provider || "mock";
        const select = document.getElementById("providerSelect");
        select.value = currentProvider;
        document.getElementById("activeModelTag").textContent = `Modèle: ${select.options[select.selectedIndex].text}`;

        if (data.kill_switch) {
            updateKillSwitchUI(true);
        }
    } catch (e) {
        console.error("Erreur chargement config BYOK", e);
    }
}

async function updateActiveProvider(providerId) {
    try {
        await fetch("/__sc/security/api/sentinel/user/llm/active", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ provider_id: providerId })
        });
    } catch (e) {
        console.error("Erreur màj provider", e);
    }
}

// Global cache of providers metadata
let _userProvidersCatalog = [];

function openByokModal() {
    const modal = document.getElementById("byokModal");
    if (modal) {
        modal.classList.add("active");
        loadUserLlmProviders();
    }
}

function closeByokModal() {
    const modal = document.getElementById("byokModal");
    if (modal) modal.classList.remove("active");
}

async function loadUserLlmProviders() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/user/llm/providers");
        const data = await res.json();
        _userProvidersCatalog = data.providers || [];

        // Update User ID badge
        const uBadge = document.getElementById("userLlmBadge");
        if (uBadge) uBadge.textContent = `Utilisateur: ${data.user_id || "Session active"}`;

        const cBadge = document.getElementById("userConnectedCountBadge");
        if (cBadge) cBadge.textContent = `${data.connected_count || 0} connecté(s)`;

        // Render providers list in left column
        const container = document.getElementById("userProvidersList");
        if (container) {
            container.innerHTML = _userProvidersCatalog.map(p => {
                const isAct = p.is_active;
                const isConn = p.is_connected;
                const statusColor = isConn ? "#10b981" : "#64748b";
                const statusText = isAct ? "Actif (Défaut)" : (isConn ? "Connecté" : "Non configuré");
                const borderStyle = isAct ? "border: 1px solid #38bdf8; background: rgba(56, 189, 248, 0.08);" : "border: 1px solid #1e293b; background: #0f172a;";

                return `
                    <div style="${borderStyle} border-radius: 8px; padding: 10px; display: flex; flex-direction: column; gap: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <i class="fa-solid ${p.icon || 'fa-microchip'}" style="color: ${isConn ? '#38bdf8' : '#64748b'}; font-size: 0.9rem;"></i>
                                <strong style="font-size: 0.82rem; color: #fff;">${escapeHtml(p.name)}</strong>
                            </div>
                            <span style="font-size: 0.68rem; padding: 2px 7px; border-radius: 10px; font-weight: 600; background: ${isConn ? 'rgba(16, 185, 129, 0.15)' : 'rgba(100, 116, 139, 0.15)'}; color: ${statusColor}; border: 1px solid ${statusColor}44;">
                                ${statusText}
                            </span>
                        </div>
                        <div style="font-size: 0.72rem; color: #94a3b8; display: flex; justify-content: space-between;">
                            <span>Modèle: <strong style="color: #cbd5e1;">${escapeHtml(p.selected_model || 'Standard')}</strong></span>
                            <span>Usage: <strong style="color: #38bdf8;">${p.usage_count || 0} req</strong></span>
                        </div>
                        ${p.masked_credentials ? `<div style="font-size: 0.68rem; color: #64748b;">Clé: ${escapeHtml(p.masked_credentials)}</div>` : ''}
                        <div style="display: flex; gap: 6px; margin-top: 4px; padding-top: 4px; border-top: 1px solid #1e293b;">
                            <button onclick="editProviderInForm('${p.provider_id}')" style="background: #1e293b; color: #38bdf8; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; cursor: pointer;">
                                <i class="fa-solid fa-pen-to-square"></i> Configurer
                            </button>
                            ${isConn ? `
                                <button onclick="setUserActiveProvider('${p.provider_id}')" style="background: ${isAct ? '#0284c7' : '#1e293b'}; color: #fff; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; cursor: pointer;">
                                    ${isAct ? '✓ Actif' : 'Activer'}
                                </button>
                                <button onclick="disconnectUserProvider('${p.provider_id}')" style="background: #1e293b; color: #ef4444; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; cursor: pointer;">
                                    <i class="fa-solid fa-trash-can"></i>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            }).join("");
        }

        // Initialize form with active or first provider
        const curSelect = document.getElementById("modalProviderSelect");
        if (curSelect) {
            curSelect.value = data.active_provider_id || "gemini";
            onProviderSelectChanged(curSelect.value);
        }

        // Synchronize main sidebar dropdown
        const mainSelect = document.getElementById("providerSelect");
        if (mainSelect && data.active_provider_id) {
            mainSelect.value = data.active_provider_id;
            currentProvider = data.active_provider_id;
            const modelTag = document.getElementById("activeModelTag");
            if (modelTag) {
                const optText = mainSelect.options[mainSelect.selectedIndex]?.text || data.active_provider_id;
                modelTag.textContent = `Modèle: ${optText}`;
            }
        }
    } catch (e) {
        console.error("Erreur chargement des fournisseurs utilisateur:", e);
    }
}

function onProviderSelectChanged(providerId) {
    const meta = _userProvidersCatalog.find(p => p.provider_id === providerId) || {};
    const titleEl = document.getElementById("formProvTitle");
    const iconEl = document.getElementById("formProvIcon");
    const docLink = document.getElementById("providerDocLink");
    const apiKeyGroup = document.getElementById("apiKeyGroup");
    const baseUrlGroup = document.getElementById("baseUrlGroup");
    const modelInput = document.getElementById("modalModel");
    const baseUrlInput = document.getElementById("modalBaseUrl");
    const quickModelsRow = document.getElementById("quickModelsRow");
    const apiKeyInput = document.getElementById("modalApiKey");
    const testResultBox = document.getElementById("testResultBox");

    if (testResultBox) testResultBox.style.display = "none";
    if (apiKeyInput) apiKeyInput.value = "";

    if (titleEl) titleEl.textContent = `Connecter : ${meta.name || providerId}`;
    if (iconEl) iconEl.className = `fa-solid ${meta.icon || 'fa-key'}`;

    if (docLink) {
        if (meta.docs_url) {
            docLink.style.display = "inline";
            docLink.href = meta.docs_url;
            docLink.textContent = `Obtenir une clé ${meta.name} →`;
        } else {
            docLink.style.display = "none";
        }
    }

    if (providerId === "mock") {
        if (apiKeyGroup) apiKeyGroup.style.display = "none";
        if (baseUrlGroup) baseUrlGroup.style.display = "none";
    } else if (providerId === "ollama") {
        if (apiKeyGroup) apiKeyGroup.style.display = "none";
        if (baseUrlGroup) baseUrlGroup.style.display = "block";
    } else {
        if (apiKeyGroup) apiKeyGroup.style.display = "block";
        if (baseUrlGroup) baseUrlGroup.style.display = "block";
    }

    if (modelInput) modelInput.value = meta.selected_model || "";
    if (baseUrlInput) baseUrlInput.value = meta.base_url || "";

    // Quick models buttons
    if (quickModelsRow) {
        const models = meta.available_models || [];
        quickModelsRow.innerHTML = models.map(m => `
            <span onclick="document.getElementById('modalModel').value='${m}'" style="background: #1e293b; border: 1px solid #334155; color: #38bdf8; font-size: 0.65rem; padding: 2px 6px; border-radius: 4px; cursor: pointer;">
                ${m}
            </span>
        `).join("");
    }
}

function editProviderInForm(providerId) {
    const select = document.getElementById("modalProviderSelect");
    if (select) {
        select.value = providerId;
        onProviderSelectChanged(providerId);
    }
}

async function saveUserProviderConnection() {
    const providerId = document.getElementById("modalProviderSelect").value;
    const apiKey = (document.getElementById("modalApiKey")?.value || "").trim();
    const model = (document.getElementById("modalModel")?.value || "").trim();
    const baseUrl = (document.getElementById("modalBaseUrl")?.value || "").trim();
    const btn = document.getElementById("saveConnBtn");

    if (btn) btn.disabled = true;

    try {
        const payload = {
            provider_id: providerId,
            model: model,
            base_url: baseUrl
        };
        if (apiKey) payload.api_key = apiKey;

        const res = await fetch("/__sc/security/api/sentinel/user/llm/connect", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.success) {
            alert(`Fournisseur ${providerId} enregistré et connecté pour votre compte !`);
            await loadUserLlmProviders();
        } else {
            alert("Erreur: " + (data.error || "Échec de connexion"));
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function testCurrentProviderConnection() {
    const providerId = document.getElementById("modalProviderSelect").value;
    const apiKey = (document.getElementById("modalApiKey")?.value || "").trim();
    const model = (document.getElementById("modalModel")?.value || "").trim();
    const baseUrl = (document.getElementById("modalBaseUrl")?.value || "").trim();
    const box = document.getElementById("testResultBox");
    const textEl = document.getElementById("testResultText");
    const btn = document.getElementById("testConnBtn");

    if (box) box.style.display = "block";
    if (textEl) {
        textEl.style.color = "#38bdf8";
        textEl.textContent = "Test de connectivité en cours avec le fournisseur...";
    }
    if (btn) btn.disabled = true;

    try {
        const res = await fetch("/__sc/security/api/sentinel/user/llm/test", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                provider_id: providerId,
                api_key: apiKey,
                model: model,
                base_url: baseUrl
            })
        });
        const data = await res.json();

        if (data.healthy) {
            textEl.style.color = "#10b981";
            textEl.textContent = `✓ Succès : Connexion établie avec l'API ${providerId} (${data.message || 'Authentification validée'}).`;
        } else {
            textEl.style.color = "#ef4444";
            textEl.textContent = `✗ Échec : ${data.error || data.message || 'Rejet par l\'API du fournisseur'}.`;
        }
    } catch (e) {
        textEl.style.color = "#ef4444";
        textEl.textContent = `Erreur réseau: ${e.message}`;
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function disconnectUserProvider(providerId) {
    if (!confirm(`Voulez-vous vraiment déconnecter votre compte ${providerId} ? Vos clés chiffrées seront définitivement supprimées de votre espace.`)) return;

    try {
        const res = await fetch(`/__sc/security/api/sentinel/user/llm/disconnect/${providerId}`, {
            method: "DELETE"
        });
        const data = await res.json();
        if (data.success) {
            await loadUserLlmProviders();
        }
    } catch (e) {
        alert("Erreur de déconnexion: " + e.message);
    }
}

async function setUserActiveProvider(providerId) {
    try {
        const res = await fetch("/__sc/security/api/sentinel/user/llm/active", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ provider_id: providerId })
        });
        const data = await res.json();
        if (data.success) {
            await loadUserLlmProviders();
        }
    } catch (e) {
        alert("Erreur: " + e.message);
    }
}

async function toggleKillSwitch() {
    const confirmed = confirm("Voulez-vous modifier l'état du Kill-Switch de sécurité ?");
    if (!confirmed) return;

    try {
        const badge = document.getElementById("guardianBadge");
        const isCurrentActive = badge.classList.contains("killed");

        const res = await fetch("/__sc/security/api/sentinel/guardian/killswitch", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ activate: !isCurrentActive })
        });
        const data = await res.json();
        updateKillSwitchUI(data.kill_switch_active);
    } catch (e) {
        console.error("Erreur killswitch", e);
    }
}

function updateKillSwitchUI(isActive) {
    const badge = document.getElementById("guardianBadge");
    const btn = document.getElementById("killSwitchBtn");
    if (isActive) {
        badge.classList.add("killed");
        badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: #ef4444;"></i> <span style="color: #ef4444;">KILL-SWITCH ACTIF (Bloqué)</span>`;
        btn.textContent = "Réactiver Guardian";
        btn.style.background = "#10b981";
        btn.style.color = "#fff";
    } else {
        badge.classList.remove("killed");
        badge.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> <span style="color: #10b981;">Guardian Zéro-Trust Actif</span>`;
        btn.innerHTML = `<i class="fa-solid fa-power-off"></i> Arrêt d'urgence`;
        btn.style.background = "rgba(239, 68, 68, 0.15)";
        btn.style.color = "#ef4444";
    }
}

// ==========================================
// SENTINEL SKILLS LIBRARY (818 SKILLS)
// ==========================================

let _skillsDebounceTimer = null;
let _skillsStatsLoaded = false;

function openSkillsLib() {
    const modal = document.getElementById("skillsLibModal");
    if (!modal) return;
    modal.classList.add("active");
    if (!_skillsStatsLoaded) {
        loadSkillsStats();
        _skillsStatsLoaded = true;
    }
    const input = document.getElementById("skillsSearchInput");
    if (input) {
        input.value = "";
        searchSkills("");
        setTimeout(() => input.focus(), 100);
    }
}

function closeSkillsLib() {
    const modal = document.getElementById("skillsLibModal");
    if (modal) modal.classList.remove("active");
}

function searchSkillsDebounced(query) {
    if (_skillsDebounceTimer) clearTimeout(_skillsDebounceTimer);
    _skillsDebounceTimer = setTimeout(() => searchSkills(query), 200);
}

async function loadSkillsStats() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/skills");
        const data = await res.json();
        const badge = document.getElementById("skillsTotalBadge");
        if (badge && data.total_skills) {
            badge.textContent = `${data.total_skills} compétences`;
        }
    } catch (e) {
        console.error("Erreur stats skills", e);
    }
}

async function searchSkills(query) {
    const container = document.getElementById("skillsResultsContainer");
    if (!container) return;
    container.innerHTML = `<div style="grid-column: 1 / -1; color: #64748b; text-align: center; padding: 2rem;">Recherche dans les 818 procédures...</div>`;

    try {
        const res = await fetch(`/__sc/security/api/sentinel/skills/search?q=${encodeURIComponent(query)}&limit=24`);
        const data = await res.json();
        const results = data.results || [];

        if (results.length === 0) {
            container.innerHTML = `<div style="grid-column: 1 / -1; color: #64748b; text-align: center; padding: 2rem;">Aucune procédure trouvée pour "${escapeHtml(query)}"</div>`;
            return;
        }

        container.innerHTML = results.map(s => {
            const safeName = escapeHtml(s.name || "");
            const safeDesc = escapeHtml(s.description || "");
            const safeSub = escapeHtml(s.subdomain || "cybersecurity");
            return `
                <div class="skill-card" onclick="selectSkillToPrompt('${safeName}')" style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 10px; cursor: pointer; transition: all 0.15s; display: flex; flex-direction: column; justify-content: space-between;" onmouseover="this.style.borderColor='#a78bfa'; this.style.transform='translateY(-2px)'" onmouseout="this.style.borderColor='#334155'; this.style.transform='none'">
                    <div>
                        <div style="font-size: 0.82rem; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                            <i class="fa-solid fa-shield-virus" style="color: #a78bfa; font-size: 0.75rem;"></i>
                            <span>${safeName}</span>
                        </div>
                        <div style="font-size: 0.72rem; color: #94a3b8; line-height: 1.35; margin-bottom: 8px;">
                            ${safeDesc.length > 110 ? safeDesc.substring(0, 110) + '...' : safeDesc}
                        </div>
                    </div>
                    <div>
                        <span style="background: rgba(167, 139, 250, 0.12); color: #c4b5fd; font-size: 0.65rem; padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(167, 139, 250, 0.25);">
                            ${safeSub}
                        </span>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        container.innerHTML = `<div style="grid-column: 1 / -1; color: #ef4444; text-align: center; padding: 2rem;">Erreur de chargement des compétences.</div>`;
    }
}

function selectSkillToPrompt(skillName) {
    closeSkillsLib();
    const chatInput = document.getElementById("chatInput");
    if (chatInput) {
        chatInput.value = `Applique la procédure de sécurité "${skillName}" sur notre environnement autorise et donne-moi les recommandations techniques.`;
        chatInput.focus();
    }
}

// ==============================================================================
// KALI LINUX MCP INTEGRATION CONTROLLER
// ==============================================================================

async function openKaliModal() {
    const modal = document.getElementById("kaliModal");
    if (modal) {
        modal.classList.add("active");
        await loadKaliStatus();
        await syncKaliTools();
        await loadKaliPending();
    }
}

function closeKaliModal() {
    const modal = document.getElementById("kaliModal");
    if (modal) modal.classList.remove("active");
}

async function loadKaliStatus() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/kali/status");
        const data = await res.json();
        const cfg = data.config || {};
        const health = data.health || {};

        const urlInput = document.getElementById("kaliInputUrl");
        if (urlInput && !urlInput.value) urlInput.value = cfg.server_url || "http://127.0.0.1:5000";

        const urlDisplay = document.getElementById("kaliServerUrlDisplay");
        if (urlDisplay) urlDisplay.textContent = `URL : ${cfg.server_url || "http://127.0.0.1:5000"}`;

        const syncDisplay = document.getElementById("kaliLastSyncDisplay");
        if (syncDisplay) syncDisplay.textContent = `Dernière synchro : ${cfg.last_sync_at || "Jamais"} (${cfg.last_sync_status || "N/A"})`;

        const latDisplay = document.getElementById("kaliLatencyDisplay");
        if (latDisplay) latDisplay.textContent = `Latence : ${health.latency_ms ? health.latency_ms + ' ms' : 'Inaccessible'}`;

        const tokenNotice = document.getElementById("kaliTokenNotice");
        if (tokenNotice) {
            tokenNotice.textContent = cfg.has_token ? `Clé enregistrée (${cfg.token_preview})` : "Aucune clé requise pour un serveur local standard";
        }

        const badge = document.getElementById("kaliConnBadge");
        const pill = document.getElementById("kaliStatusPill");
        if (health.connected) {
            if (badge) {
                badge.style.background = "#059669";
                badge.style.color = "#ecfdf5";
                badge.textContent = `Connecté (${health.version || "kali-mcp"})`;
            }
            if (pill) {
                pill.style.background = "rgba(16, 185, 129, 0.2)";
                pill.style.borderColor = "rgba(16, 185, 129, 0.5)";
                pill.style.color = "#34d399";
                pill.textContent = "ONLINE";
            }
        } else {
            if (badge) {
                badge.style.background = "#b91c1c";
                badge.style.color = "#fef2f2";
                badge.textContent = "Hors ligne / Simulation";
            }
            if (pill) {
                pill.style.background = "rgba(239, 68, 68, 0.2)";
                pill.style.borderColor = "rgba(239, 68, 68, 0.5)";
                pill.style.color = "#f87171";
                pill.textContent = "OFFLINE";
            }
        }
    } catch (e) {
        console.error("Erreur de chargement du statut Kali MCP:", e);
    }
}

async function saveKaliConfig() {
    const url = (document.getElementById("kaliInputUrl")?.value || "").trim();
    const token = (document.getElementById("kaliInputToken")?.value || "").trim();

    try {
        const payload = { server_url: url };
        if (token) payload.api_token = token;

        const res = await fetch("/__sc/security/api/sentinel/kali/config", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            alert("Configuration Kali MCP enregistrée avec succès !");
            await loadKaliStatus();
            await syncKaliTools();
        } else {
            alert("Erreur: " + (data.error || "Échec de sauvegarde."));
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function syncKaliTools() {
    const list = document.getElementById("kaliToolsList");
    if (!list) return;

    try {
        const res = await fetch("/__sc/security/api/sentinel/kali/sync", {
            method: "POST",
            headers: {"Content-Type": "application/json"}
        });
        const data = await res.json();
        const discovery = data.discovery || {};
        const tools = discovery.tools || [];

        const badgeCount = document.getElementById("kaliToolsCountBadge");
        if (badgeCount) badgeCount.textContent = `${tools.length} outils`;

        list.innerHTML = tools.map(t => {
            const isReady = t.is_available;
            const badgeBg = isReady ? "rgba(16, 185, 129, 0.15)" : "rgba(56, 189, 248, 0.1)";
            const badgeBorder = isReady ? "rgba(16, 185, 129, 0.35)" : "rgba(56, 189, 248, 0.25)";
            const badgeColor = isReady ? "#34d399" : "#38bdf8";
            const icon = isReady ? "fa-check" : "fa-shield-halved";

            return `
                <div style="background: ${badgeBg}; border: 1px solid ${badgeBorder}; border-radius: 6px; padding: 4px 8px; font-size: 0.72rem; color: ${badgeColor}; display: flex; align-items: center; gap: 6px;" title="${escapeHtml(t.description)}">
                    <i class="fa-solid ${icon}"></i>
                    <strong>${escapeHtml(t.name)}</strong>
                    <span style="font-size: 0.65rem; opacity: 0.8;">(${escapeHtml(t.category)})</span>
                </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Erreur de synchronisation des outils Kali:", e);
    }
}

async function executeKaliToolManual() {
    const tool = document.getElementById("kaliExecToolSelect")?.value;
    const target = (document.getElementById("kaliExecTarget")?.value || "").trim();
    const argsRaw = (document.getElementById("kaliExecArgs")?.value || "").trim();
    const consoleBox = document.getElementById("kaliOutputConsole");
    const statusBadge = document.getElementById("kaliExecStatusBadge");
    const btn = document.getElementById("kaliExecBtn");

    if (!target) {
        alert("Veuillez saisir une cible autorisée.");
        return;
    }

    const customArgs = argsRaw ? argsRaw.split(/\s+/) : [];

    if (consoleBox) consoleBox.textContent = `// Transmission de l'opération ${tool} vers Kali MCP...\n// Contrôle Guardian en cours...\n`;
    if (statusBadge) statusBadge.textContent = "Exécution...";
    if (btn) btn.disabled = true;

    try {
        const res = await fetch("/__sc/security/api/sentinel/kali/execute", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                tool: tool,
                target: target,
                custom_args: customArgs
            })
        });
        const data = await res.json();

        if (statusBadge) {
            statusBadge.textContent = data.status || (data.success ? "Succès" : "Erreur");
            statusBadge.style.color = data.success ? "#34d399" : "#f87171";
        }

        if (consoleBox) {
            let output = `[COMMANDE EXÉCUTÉE] : ${data.command || tool}\n`;
            output += `[STATUT] : ${data.status} (Code retour: ${data.returncode})\n`;
            output += `[DURÉE]  : ${data.duration_seconds || 0}s\n`;
            output += `------------------------------------------------------------\n`;
            if (data.stdout) output += data.stdout + "\n";
            if (data.stderr) output += `[STDERR / INFO] : \n${data.stderr}\n`;
            if (data.error) output += `[ERREUR GUARDIAN / SYSTÈME] : ${data.error}\n`;
            consoleBox.textContent = output;
        }
    } catch (e) {
        if (consoleBox) consoleBox.textContent = `[ERREUR DE COMMUNICATION] : ${e.message}`;
        if (statusBadge) statusBadge.textContent = "Échec";
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ------------------------------------------------------------------------
// Demandes de l'agent en attente d'approbation humaine (jamais d'exécution
// automatique : request_execution() ne fait que déposer la demande, c'est
// approveKaliPending() ici qui déclenche réellement l'exécution).
// ------------------------------------------------------------------------

async function loadKaliPending() {
    const list = document.getElementById("kaliPendingList");
    const countBadge = document.getElementById("kaliPendingCountBadge");
    if (!list) return;

    try {
        const res = await fetch("/__sc/security/api/sentinel/kali/pending");
        if (res.status === 401) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Connexion admin requise.</div>`;
            return;
        }
        const data = await res.json();
        const pending = data.pending || [];

        if (countBadge) countBadge.textContent = `${pending.length} en attente`;

        if (!pending.length) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Aucune demande en attente.</div>`;
            return;
        }

        list.innerHTML = pending.map(p => {
            const args = Array.isArray(p.custom_args) ? p.custom_args.join(" ") : "";
            return `
                <div style="background: #1a1406; border: 1px solid #ca8a0455; border-radius: 6px; padding: 8px 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
                        <div style="font-size: 0.78rem; color: #fde68a;">
                            <strong>${escapeHtml(p.tool_name)}</strong> sur <strong>${escapeHtml(p.target)}</strong>
                        </div>
                        <span style="font-size: 0.65rem; color: #94a3b8; white-space: nowrap;">${escapeHtml(p.created_at || "")}</span>
                    </div>
                    ${args ? `<div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px;">args : ${escapeHtml(args)}</div>` : ""}
                    ${p.reason ? `<div style="font-size: 0.7rem; color: #cbd5e1; margin-top: 4px;">Raison (agent) : ${escapeHtml(p.reason)}</div>` : ""}
                    <div style="font-size: 0.65rem; color: #64748b; margin-top: 2px;">Demandé par : ${escapeHtml(p.requested_by || "agent")}</div>
                    <div style="display: flex; gap: 6px; margin-top: 8px;">
                        <button onclick="approveKaliPending('${p.id}')" style="flex: 1; background: #059669; color: #ecfdf5; border: none; padding: 5px 10px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; cursor: pointer;">
                            <i class="fa-solid fa-check"></i> Approuver &amp; exécuter
                        </button>
                        <button onclick="denyKaliPending('${p.id}')" style="flex: 1; background: #1e293b; color: #f87171; border: 1px solid #ef444455; padding: 5px 10px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; cursor: pointer;">
                            <i class="fa-solid fa-xmark"></i> Refuser
                        </button>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Erreur de chargement des demandes Kali en attente:", e);
    }
}

async function approveKaliPending(approvalId) {
    if (!confirm("Approuver cette demande ? L'outil Kali va s'exécuter réellement sur la cible indiquée.")) return;
    try {
        const res = await fetch(`/__sc/security/api/sentinel/kali/approve/${encodeURIComponent(approvalId)}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"}
        });
        const data = await res.json();
        if (!res.ok || data.success === false) {
            alert("Erreur: " + (data.error || "Échec de l'approbation."));
        }
        await loadKaliPending();

        // Reflect the result in the execution console too
        const consoleBox = document.getElementById("kaliOutputConsole");
        const statusBadge = document.getElementById("kaliExecStatusBadge");
        if (consoleBox && data.status) {
            let output = `[APPROUVÉ MANUELLEMENT] : ${data.command || data.tool}\n`;
            output += `[STATUT] : ${data.status} (Code retour: ${data.returncode})\n`;
            if (data.stdout) output += `------------------------------------------------------------\n${data.stdout}\n`;
            if (data.stderr) output += `[STDERR / INFO] : \n${data.stderr}\n`;
            if (data.error) output += `[ERREUR] : ${data.error}\n`;
            consoleBox.textContent = output;
        }
        if (statusBadge && data.status) {
            statusBadge.textContent = data.status;
            statusBadge.style.color = data.success ? "#34d399" : "#f87171";
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function denyKaliPending(approvalId) {
    const reason = prompt("Raison du refus (optionnel) :", "") || "";
    try {
        const res = await fetch(`/__sc/security/api/sentinel/kali/deny/${encodeURIComponent(approvalId)}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ reason })
        });
        const data = await res.json();
        if (!res.ok || data.success === false) {
            alert("Erreur: " + (data.error || "Échec du refus."));
        }
        await loadKaliPending();
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

// ==============================================================================
// EXTERNAL OPEN-SOURCE SCANNERS UI LOGIC (Nuclei, ZAP, Semgrep, Trivy, Gitleaks)
// ==============================================================================

async function openScannersModal() {
    const modal = document.getElementById("scannersModal");
    if (modal) {
        modal.classList.add("active");
        await loadScannersTools();
        await loadScannersPending();
    }
}

function closeScannersModal() {
    const modal = document.getElementById("scannersModal");
    if (modal) modal.classList.remove("active");
}

async function loadScannersTools() {
    const list = document.getElementById("scannersToolsList");
    const countBadge = document.getElementById("scannersInstalledCountBadge");
    if (!list) return;
    try {
        const res = await fetch("/__sc/security/api/sentinel/scanners/tools");
        const data = await res.json();
        const tools = data.tools || [];
        const installedCount = tools.filter(t => t.is_installed).length;
        if (countBadge) countBadge.textContent = `${installedCount}/${tools.length} installés`;

        list.innerHTML = tools.map(t => `
            <div style="background: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="font-size: 0.82rem; color: #fff;">${escapeHtml(t.name)}</strong>
                    <span style="font-size: 0.65rem; padding: 2px 7px; border-radius: 10px; font-weight: 600; background: ${t.is_installed ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color: ${t.is_installed ? '#34d399' : '#f87171'}; border: 1px solid ${t.is_installed ? '#34d39944' : '#ef444444'};">
                        ${t.is_installed ? 'Installé' : 'Non installé'}
                    </span>
                </div>
                <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 4px;">${escapeHtml(t.description)}</div>
                <div style="font-size: 0.65rem; color: #64748b; margin-top: 2px;">Cible : ${t.target_type === 'network' ? 'URL / hôte réseau' : 'chemin local (projet)'}</div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Erreur chargement catalogue scanners:", e);
    }
}

async function executeScannerManual() {
    const tool = document.getElementById("scannerExecToolSelect")?.value;
    const target = (document.getElementById("scannerExecTarget")?.value || "").trim();
    const consoleBox = document.getElementById("scannerOutputConsole");
    const statusBadge = document.getElementById("scannerExecStatusBadge");
    const btn = document.getElementById("scannerExecBtn");

    if (!target) {
        alert("Veuillez saisir une cible (URL autorisée ou chemin local).");
        return;
    }

    if (consoleBox) consoleBox.textContent = `// Transmission de l'opération ${tool} vers le Guardian...\n// Validation en cours...\n`;
    if (statusBadge) statusBadge.textContent = "Exécution...";
    if (btn) btn.disabled = true;

    try {
        const res = await fetch("/__sc/security/api/sentinel/scanners/execute", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ tool_id: tool, target: target })
        });
        const data = await res.json();

        if (statusBadge) {
            statusBadge.textContent = data.status || (data.success ? "Succès" : "Erreur");
            statusBadge.style.color = data.success ? "#34d399" : "#f87171";
        }

        if (consoleBox) {
            let output = `[OUTIL] : ${tool} sur ${target}\n`;
            output += `[STATUT] : ${data.status} (${data.findings_count || 0} résultat(s), ${data.duration_seconds || 0}s)\n`;
            output += `------------------------------------------------------------\n`;
            if (data.findings && data.findings.length) {
                output += JSON.stringify(data.findings, null, 2);
            } else if (data.error) {
                output += `[ERREUR] : ${data.error}`;
            } else {
                output += "Aucun résultat retourné.";
            }
            consoleBox.textContent = output;
        }
    } catch (e) {
        if (consoleBox) consoleBox.textContent = `// Erreur réseau : ${e.message}`;
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function loadScannersPending() {
    const list = document.getElementById("scannersPendingList");
    const countBadge = document.getElementById("scannersPendingCountBadge");
    if (!list) return;

    try {
        const res = await fetch("/__sc/security/api/sentinel/scanners/pending");
        if (res.status === 401) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Connexion admin requise.</div>`;
            return;
        }
        const data = await res.json();
        const pending = data.pending || [];

        if (countBadge) countBadge.textContent = `${pending.length} en attente`;

        if (!pending.length) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Aucune demande en attente.</div>`;
            return;
        }

        list.innerHTML = pending.map(p => `
            <div style="background: #1a1406; border: 1px solid #ca8a0455; border-radius: 6px; padding: 8px 10px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
                    <div style="font-size: 0.78rem; color: #fde68a;">
                        <strong>${escapeHtml(p.tool_id)}</strong> sur <strong>${escapeHtml(p.target)}</strong>
                    </div>
                    <span style="font-size: 0.65rem; color: #94a3b8; white-space: nowrap;">${escapeHtml(p.created_at || "")}</span>
                </div>
                ${p.reason ? `<div style="font-size: 0.7rem; color: #cbd5e1; margin-top: 4px;">Raison (agent) : ${escapeHtml(p.reason)}</div>` : ""}
                <div style="font-size: 0.65rem; color: #64748b; margin-top: 2px;">Demandé par : ${escapeHtml(p.requested_by || "agent")}</div>
                <div style="display: flex; gap: 6px; margin-top: 8px;">
                    <button onclick="approveScannerPending('${p.id}')" style="flex: 1; background: #059669; color: #ecfdf5; border: none; padding: 5px 10px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; cursor: pointer;">
                        <i class="fa-solid fa-check"></i> Approuver &amp; exécuter
                    </button>
                    <button onclick="denyScannerPending('${p.id}')" style="flex: 1; background: #1e293b; color: #f87171; border: 1px solid #ef444455; padding: 5px 10px; border-radius: 5px; font-size: 0.72rem; font-weight: 700; cursor: pointer;">
                        <i class="fa-solid fa-xmark"></i> Refuser
                    </button>
                </div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Erreur de chargement des demandes scanners en attente:", e);
    }
}

async function approveScannerPending(approvalId) {
    if (!confirm("Approuver cette demande ? Le scanner va s'exécuter réellement sur la cible indiquée.")) return;
    try {
        const res = await fetch(`/__sc/security/api/sentinel/scanners/approve/${encodeURIComponent(approvalId)}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"}
        });
        const data = await res.json();
        if (!res.ok || data.success === false) {
            alert("Erreur: " + (data.error || "Échec de l'approbation."));
        }
        await loadScannersPending();

        const consoleBox = document.getElementById("scannerOutputConsole");
        const statusBadge = document.getElementById("scannerExecStatusBadge");
        if (consoleBox && data.status) {
            let output = `[APPROUVÉ MANUELLEMENT] : ${data.tool} sur ${data.target}\n`;
            output += `[STATUT] : ${data.status} (${data.findings_count || 0} résultat(s))\n`;
            if (data.findings && data.findings.length) output += `------------------------------------------------------------\n${JSON.stringify(data.findings, null, 2)}\n`;
            if (data.error) output += `[ERREUR] : ${data.error}\n`;
            consoleBox.textContent = output;
        }
        if (statusBadge && data.status) {
            statusBadge.textContent = data.status;
            statusBadge.style.color = data.success ? "#34d399" : "#f87171";
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function denyScannerPending(approvalId) {
    const reason = prompt("Raison du refus (optionnel) :", "") || "";
    try {
        const res = await fetch(`/__sc/security/api/sentinel/scanners/deny/${encodeURIComponent(approvalId)}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ reason })
        });
        const data = await res.json();
        if (!res.ok || data.success === false) {
            alert("Erreur: " + (data.error || "Échec du refus."));
        }
        await loadScannersPending();
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

// ==============================================================================
// REAL-TIME SELF-LEARNING SHIELD UI LOGIC
// ==============================================================================

async function openShieldModal() {
    const modal = document.getElementById("shieldModal");
    if (modal) {
        modal.classList.add("active");
        await Promise.all([loadShieldStatus(), loadShieldAgentKeys(), loadShieldIncidents(), loadShieldSignatures()]);
    }
}

function closeShieldModal() {
    const modal = document.getElementById("shieldModal");
    if (modal) modal.classList.remove("active");
}

const SHIELD_TIER_COLORS = {
    NORMAL: "#059669", ALERT: "#d97706", DEFENSIVE: "#dc2626", EMERGENCY: "#991b1b"
};

async function loadShieldStatus() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/shield/status");
        if (res.status === 401) return;
        const data = await res.json();
        const tier = data.tier || "NORMAL";
        const color = SHIELD_TIER_COLORS[tier] || "#059669";
        const badge = document.getElementById("shieldTierBadge");
        if (badge) { badge.textContent = tier; badge.style.background = color; }
        const pill = document.getElementById("shieldTierPill");
        if (pill) { pill.textContent = tier; pill.style.borderColor = color + "55"; pill.style.background = color + "22"; }
    } catch (e) {
        console.error("Erreur chargement statut bouclier:", e);
    }
}

async function provisionShieldAgent() {
    const domain = (document.getElementById("shieldProvisionDomain")?.value || "").trim();
    const box = document.getElementById("shieldNewKeyBox");
    if (!domain) { alert("Veuillez saisir un domaine."); return; }
    try {
        const res = await fetch("/__sc/security/api/sentinel/agent/provision", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ domain })
        });
        const data = await res.json();
        if (!data.success) {
            alert("Erreur: " + (data.error || "Échec de l'émission de la clé."));
            return;
        }
        if (box) {
            box.style.display = "block";
            box.innerHTML = `Clé d'agent pour <strong>${escapeHtml(data.domain)}</strong> :<br><code>${escapeHtml(data.api_key)}</code><br><small style="color:#64748b;">Copie-la dans le snippet middleware installé sur ce site - elle ne sera plus affichée en clair.</small>`;
        }
        await loadShieldAgentKeys();
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function loadShieldAgentKeys() {
    const list = document.getElementById("shieldAgentKeysList");
    if (!list) return;
    try {
        const res = await fetch("/__sc/security/api/sentinel/agent/keys");
        if (res.status === 401) return;
        const data = await res.json();
        const keys = data.keys || [];
        if (!keys.length) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Aucun site protégé pour le moment.</div>`;
            return;
        }
        list.innerHTML = keys.map(k => `
            <div style="background: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 7px 10px; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <strong style="font-size: 0.8rem; color: #fff;">${escapeHtml(k.domain)}</strong>
                    <div style="font-size: 0.65rem; color: #64748b;">${k.is_active ? 'Actif' : 'Révoqué'} &bull; dernier contact: ${escapeHtml(k.last_seen_at || 'jamais')}</div>
                </div>
                ${k.is_active ? `<button onclick="revokeShieldAgent('${escapeHtml(k.domain)}')" style="background:#1e293b; color:#f87171; border:1px solid #ef444455; padding:4px 8px; border-radius:5px; font-size:0.68rem; cursor:pointer;">Révoquer</button>` : ""}
            </div>
        `).join("");
    } catch (e) {
        console.error("Erreur chargement des clés d'agent:", e);
    }
}

async function revokeShieldAgent(domain) {
    if (!confirm(`Révoquer la clé d'agent pour ${domain} ? Ce site ne sera plus protégé.`)) return;
    try {
        await fetch("/__sc/security/api/sentinel/agent/revoke", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ domain })
        });
        await loadShieldAgentKeys();
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function loadShieldIncidents() {
    const list = document.getElementById("shieldIncidentsList");
    const countBadge = document.getElementById("shieldIncidentsCountBadge");
    if (!list) return;
    try {
        const res = await fetch("/__sc/security/api/sentinel/incidents");
        if (res.status === 401) return;
        const data = await res.json();
        const incidents = data.incidents || [];
        if (countBadge) countBadge.textContent = `${incidents.length} incident(s)`;
        if (!incidents.length) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Aucune attaque détectée.</div>`;
            return;
        }
        list.innerHTML = incidents.map(i => `
            <div style="background: #1a0a0a; border: 1px solid #ef444444; border-radius: 6px; padding: 7px 10px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="font-size: 0.78rem; color: #fca5a5;">${escapeHtml(i.severity)} &bull; ${escapeHtml(i.source_ip)}</strong>
                    <span style="font-size: 0.62rem; color: #64748b;">${escapeHtml(i.updated_at || "")}</span>
                </div>
                <div style="font-size: 0.72rem; color: #cbd5e1; margin-top: 3px;">${escapeHtml(i.summary)}</div>
                <div style="font-size: 0.65rem; color: #64748b; margin-top: 2px;">Action : ${escapeHtml(i.action_taken)} &bull; Domaine : ${escapeHtml(i.domain)}</div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Erreur chargement threat feed:", e);
    }
}

async function loadShieldSignatures() {
    const list = document.getElementById("shieldSignaturesList");
    const countBadge = document.getElementById("shieldSignaturesCountBadge");
    if (!list) return;
    try {
        const res = await fetch("/__sc/security/api/sentinel/signatures/learned");
        if (res.status === 401) return;
        const data = await res.json();
        const sigs = data.signatures || [];
        if (countBadge) countBadge.textContent = sigs.length;
        if (!sigs.length) {
            list.innerHTML = `<div style="color: #475569; font-size: 0.78rem; text-align: center; padding: 10px;">Rien appris pour l'instant.</div>`;
            return;
        }
        list.innerHTML = sigs.map(s => `
            <div style="background: #111827; border: 1px solid #1e293b; border-radius: 6px; padding: 7px 10px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="font-size: 0.76rem; color: ${s.is_active ? '#fff' : '#64748b'};">${escapeHtml(s.category)}</strong>
                    <span style="font-size: 0.62rem; color: ${s.origin === 'human_taught' ? '#a78bfa' : '#f87171'};">${s.origin === 'human_taught' ? 'Enseignée' : 'Auto-apprise'}</span>
                </div>
                <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 2px; font-family: monospace; word-break: break-all;">${escapeHtml(s.example_payload || "")}</div>
                <div style="font-size: 0.6rem; color: #64748b; margin-top: 2px; display:flex; justify-content:space-between;">
                    <span>${s.hit_count} occurrence(s) &bull; ${s.is_active ? 'active' : 'désactivée'}</span>
                    <a href="#" onclick="event.preventDefault(); ${s.is_active ? `deactivateShieldSignature(${s.id})` : `reactivateShieldSignature(${s.id})`}" style="color:#64748b;">${s.is_active ? 'Désactiver' : 'Réactiver'}</a>
                </div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Erreur chargement signatures apprises:", e);
    }
}

async function deactivateShieldSignature(id) {
    const reason = prompt("Pourquoi cette règle est-elle une erreur ? (ex: trop large, a bloqué du trafic légitime) - gardé en mémoire pour ne pas répéter l'erreur :", "") || "";
    await fetch(`/__sc/security/api/sentinel/signatures/${id}/deactivate`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ reason })
    });
    await loadShieldSignatures();
}

async function reactivateShieldSignature(id) {
    await fetch(`/__sc/security/api/sentinel/signatures/${id}/reactivate`, { method: "POST" });
    await loadShieldSignatures();
}

async function teachShieldSignature() {
    const category = (document.getElementById("teachCategory")?.value || "").trim();
    const payload = (document.getElementById("teachPayload")?.value || "").trim();
    if (!payload) { alert("Colle le payload exact qui a contourné le bouclier."); return; }
    try {
        const res = await fetch("/__sc/security/api/sentinel/signatures/teach", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ category, severity: "HIGH", example_payload: payload })
        });
        const data = await res.json();
        if (!data.success) {
            alert("Erreur: " + (data.error || "Échec de l'apprentissage."));
            return;
        }
        document.getElementById("teachCategory").value = "";
        document.getElementById("teachPayload").value = "";
        await loadShieldSignatures();
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

// ==============================================================================
// PENTAGI AUTONOMOUS PENTESTING ENGINE UI LOGIC
// ==============================================================================

let selectedPentagiCampaignId = null;

function openPentagiModal() {
    const modal = document.getElementById("pentagiModal");
    if (modal) {
        modal.classList.add("active");
        loadPentagiStatus();
        loadPentagiCampaigns();
    }
}

function closePentagiModal() {
    const modal = document.getElementById("pentagiModal");
    if (modal) modal.classList.remove("active");
}

async function loadPentagiStatus() {
    try {
        const res = await fetch("/__sc/security/api/sentinel/pentagi/status");
        const data = await res.json();
        const cfg = data.config || {};
        const health = data.health || {};

        const badge = document.getElementById("pentagiConnBadge");
        const pill = document.getElementById("pentagiStatusPill");
        const urlDisplay = document.getElementById("pentagiServerUrlDisplay");
        const workersDisplay = document.getElementById("pentagiWorkersDisplay");
        const syncDisplay = document.getElementById("pentagiLastSyncDisplay");
        const urlInput = document.getElementById("pentagiInputUrl");

        if (urlInput && !urlInput.value) {
            urlInput.value = cfg.server_url || "http://127.0.0.1:8443";
        }
        if (urlDisplay) {
            urlDisplay.innerHTML = `<i class="fa-solid fa-server"></i> URL : ${escapeHtml(cfg.server_url || "http://127.0.0.1:8443")}`;
        }
        if (workersDisplay) {
            workersDisplay.innerHTML = `<i class="fa-solid fa-cubes"></i> Workers Sandbox : ${health.workers_available || 1} actif(s)`;
        }
        if (syncDisplay) {
            syncDisplay.innerHTML = `<i class="fa-solid fa-clock"></i> Synchro : ${escapeHtml(health.checked_at || "N/A")}`;
        }

        if (health.is_connected) {
            if (badge) {
                badge.style.background = "#059669";
                badge.style.color = "#ecfdf5";
                badge.textContent = `Connecté (${health.version || "PentAGI Engine"})`;
            }
            if (pill) {
                pill.style.background = "rgba(16, 185, 129, 0.2)";
                pill.style.borderColor = "rgba(16, 185, 129, 0.5)";
                pill.style.color = "#34d399";
                pill.textContent = "ONLINE";
            }
        } else {
            if (badge) {
                badge.style.background = "#ca8a04";
                badge.style.color = "#fef9c3";
                badge.textContent = "Mode Simulation / Sandbox Ulton";
            }
            if (pill) {
                pill.style.background = "rgba(202, 138, 4, 0.2)";
                pill.style.borderColor = "rgba(202, 138, 4, 0.5)";
                pill.style.color = "#facc15";
                pill.textContent = "SANDBOX";
            }
        }
    } catch (e) {
        console.error("Erreur de chargement du statut PentAGI:", e);
    }
}

async function savePentagiConfig() {
    const url = (document.getElementById("pentagiInputUrl")?.value || "").trim();
    const token = (document.getElementById("pentagiInputToken")?.value || "").trim();

    try {
        const payload = { server_url: url };
        if (token) payload.api_token = token;

        const res = await fetch("/__sc/security/api/sentinel/pentagi/config", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
            alert("Configuration PentAGI enregistrée avec succès !");
            await loadPentagiStatus();
        } else {
            alert("Erreur: " + (data.error || "Échec de sauvegarde"));
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}

async function launchPentagiCampaign() {
    const target = (document.getElementById("pentagiTargetInput")?.value || "").trim();
    const goal = (document.getElementById("pentagiGoalInput")?.value || "").trim();
    const depth = (document.getElementById("pentagiDepthSelect")?.value || "standard").trim();
    const btn = document.getElementById("pentagiLaunchBtn");

    if (!target) {
        alert("Veuillez renseigner un actif autorisé (URL ou domaine).");
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Audit en cours sous contrôle Guardian...`;
    }

    try {
        const res = await fetch("/__sc/security/api/sentinel/pentagi/campaigns", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ target, goal, depth })
        });
        const data = await res.json();

        if (res.ok && data.success) {
            alert(`Campagne PentAGI ${data.campaign_id} terminée avec succès ! (${data.findings_count} vulnérabilité(s) identifiée(s))`);
            await loadPentagiCampaigns();
            selectPentagiCampaign(data.campaign_id);
        } else {
            alert(`Opération rejetée : ${data.error || "Échec de lancement de la campagne"}`);
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-rocket"></i> Lancer la Campagne sous Contrôle Guardian`;
        }
    }
}

async function loadPentagiCampaigns() {
    const list = document.getElementById("pentagiCampaignsList");
    const countBadge = document.getElementById("pentagiCampaignsCount");
    if (!list) return;

    try {
        const res = await fetch("/__sc/security/api/sentinel/pentagi/campaigns");
        const data = await res.json();
        const campaigns = data.campaigns || [];

        if (countBadge) countBadge.textContent = `${campaigns.length} campagne(s)`;

        if (campaigns.length === 0) {
            list.innerHTML = `<div style="color: #64748b; font-size: 0.78rem; text-align: center; padding: 12px;">Aucune campagne récente</div>`;
            return;
        }

        list.innerHTML = campaigns.map(c => {
            const isSelected = c.id === selectedPentagiCampaignId;
            const statusColor = c.status === "completed" ? "#34d399" : (c.status === "stopped" ? "#f87171" : "#38bdf8");
            return `
                <div onclick="selectPentagiCampaign('${escapeHtml(c.id)}')" style="background: ${isSelected ? '#1e293b' : '#0a0f1d'}; border: 1px solid ${isSelected ? '#10b981' : '#1e293b'}; border-radius: 6px; padding: 8px 10px; cursor: pointer; transition: background 0.15s; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 700; color: #fff; font-size: 0.78rem;">${escapeHtml(c.target)}</div>
                        <div style="font-size: 0.7rem; color: #64748b;">${escapeHtml(c.created_at)} &bull; ${escapeHtml(c.goal || "")}</div>
                    </div>
                    <div style="text-align: right;">
                        <span style="font-size: 0.68rem; font-weight: 700; color: ${statusColor}; text-transform: uppercase;">${escapeHtml(c.status)}</span>
                        <div style="font-size: 0.7rem; color: #facc15;">${c.findings_count} faiblesses</div>
                    </div>
                </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Erreur de chargement des campagnes PentAGI:", e);
    }
}

async function selectPentagiCampaign(campaignId) {
    selectedPentagiCampaignId = campaignId;
    const detailBox = document.getElementById("pentagiDetailFindings");
    const detailTitle = document.getElementById("pentagiDetailTitle");
    const remediateBtn = document.getElementById("pentagiRemediateBtn");

    if (!detailBox) return;

    try {
        const res = await fetch(`/__sc/security/api/sentinel/pentagi/campaigns/${encodeURIComponent(campaignId)}`);
        const data = await res.json();
        const camp = data.campaign || {};
        const findings = camp.findings || [];

        if (detailTitle) {
            detailTitle.textContent = `Campagne ${camp.id} (${camp.target}) &bull; ${findings.length} découverte(s)`;
        }
        if (remediateBtn) {
            remediateBtn.style.display = findings.length > 0 ? "inline-block" : "none";
        }

        if (findings.length === 0) {
            detailBox.innerHTML = `<div style="color: #34d399; text-align: center; padding: 16px;"><i class="fa-solid fa-circle-check"></i> Aucune faiblesse critique identifiée sur cette cible.</div>`;
            return;
        }

        detailBox.innerHTML = findings.map(f => {
            const sev = f.severity || "MEDIUM";
            const sevColor = sev === "HIGH" ? "#f87171" : (sev === "MEDIUM" ? "#fbbf24" : "#38bdf8");
            return `
                <div style="background: #090d16; border-left: 3px solid ${sevColor}; border: 1px solid #1e293b; border-left-width: 3px; border-radius: 4px; padding: 8px 10px; margin-bottom: 6px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                        <span style="font-weight: 700; color: #fff; font-size: 0.78rem;">${escapeHtml(f.title || f.id)}</span>
                        <span style="font-size: 0.68rem; font-weight: 700; color: ${sevColor}; background: rgba(0,0,0,0.4); padding: 1px 6px; border-radius: 4px;">${sev}</span>
                    </div>
                    <p style="margin: 0; font-size: 0.72rem; color: #94a3b8;">${escapeHtml(f.description || "")}</p>
                </div>
            `;
        }).join("");

        await loadPentagiCampaigns();
    } catch (e) {
        detailBox.innerHTML = `<div style="color: #f87171; padding: 10px;">Erreur de chargement: ${e.message}</div>`;
    }
}

async function remediateSelectedCampaign() {
    if (!selectedPentagiCampaignId) {
        alert("Veuillez sélectionner une campagne.");
        return;
    }

    try {
        const res = await fetch(`/__sc/security/api/sentinel/pentagi/campaigns/${encodeURIComponent(selectedPentagiCampaignId)}/remediate`, {
            method: "POST"
        });
        const data = await res.json();
        if (data.success) {
            alert(`${data.remediations_created} plan(s) de remédiation formels avec patchs diff générés dans le module de Remédiation Ulton !`);
        } else {
            alert("Erreur: " + (data.error || "Échec de génération"));
        }
    } catch (e) {
        alert("Erreur réseau: " + e.message);
    }
}



